"""CPU demo: synthetic dataset, local metric, pinned Hub model files."""
import json
import tempfile
from pathlib import Path

import evaluate
import transformers
from huggingface_hub import hf_hub_download
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from aigov_py.huggingface_evaluate import capture_evaluate_result
from aigov_py.huggingface_evaluation import verify_evaluation_evidence
from aigov_py.huggingface_provenance import capture_hub_provenance, manifest_digest, verify_artifact
from aigov_py.huggingface_transformers import capture_transformers_configuration

REPO = "hf-internal-testing/tiny-random-bert"
FILES = ["config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json", "vocab.txt"]


def main():
    manifest = capture_hub_provenance(REPO, FILES, token=False)
    anchor = manifest_digest(manifest)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name in FILES:
            source = hf_hub_download(REPO, name, revision=manifest["commit"], token=False)
            target = root / name
            target.write_bytes(Path(source).read_bytes())
            if not verify_artifact(manifest, name, target, expected_manifest_sha256=anchor):
                raise RuntimeError("Artifact mismatch")
        tokenizer = AutoTokenizer.from_pretrained(root, local_files_only=True, trust_remote_code=False)
        model = AutoModelForSequenceClassification.from_pretrained(
            root, local_files_only=True, trust_remote_code=False, use_safetensors=True)
        model.eval()
        import torch
        samples = ["a good day", "a bad day"]
        labels = [1, 0]
        with torch.inference_mode():
            predictions = model(**tokenizer(samples, padding=True, return_tensors="pt")).logits.argmax(-1).tolist()
        # Local Evaluate metric avoids downloading executable metric scripts.
        class Accuracy(evaluate.Metric):
            def _info(self):
                import datasets
                return evaluate.MetricInfo(
                    description="Toy accuracy", citation="", inputs_description="Binary labels",
                    features=datasets.Features({"predictions": datasets.Value("int64"),
                                                "references": datasets.Value("int64")}))
            def _compute(self, predictions, references):
                return {"accuracy": sum(a == b for a, b in zip(predictions, references)) / len(references)}
        result = Accuracy().compute(predictions=predictions, references=labels)
        configuration = {"model": capture_transformers_configuration(
            model, transformers_version=transformers.__version__),
            "evaluate_version": evaluate.__version__, "torch_version": str(torch.__version__),
            "metric": "local_accuracy_v1", "device": "cpu"}
        evidence = capture_evaluate_result(
            result, run_id="toy-evaluation",
            model_manifest_sha256=anchor,
            dataset_manifest_sha256=manifest_digest({"samples": samples, "labels": labels}),
            policy_sha256=manifest_digest({"demo_policy": "record_only"}),
            configuration_sha256=manifest_digest(configuration))
        trusted = manifest_digest(evidence)
        assert verify_evaluation_evidence(evidence, expected_sha256=trusted)
        print(json.dumps({"evidence": evidence, "demo_anchor": trusted}, indent=2))
        evidence["metrics"]["accuracy"] = -1.0
        assert not verify_evaluation_evidence(evidence, expected_sha256=trusted)
        print("Modified evidence rejected")


if __name__ == "__main__":
    main()
