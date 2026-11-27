import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";

const html = await readFile(new URL("./index.html", import.meta.url), "utf8");
const start = html.indexOf("    function hex(bytes)");
const end = html.indexOf("    function renderReasons(", start);
assert.notEqual(start, -1, "viewer hash functions must exist");
assert.notEqual(end, -1, "viewer hash functions must end before rendering code");
const source = `const MAX_ROWS = 5000;\n${html.slice(start, end)}\nreturn verifyHashChain;`;
const makeVerifier = new Function("crypto", "TextEncoder", "Uint8Array", source);
const verifyHashChain = makeVerifier(webcrypto, TextEncoder, Uint8Array);

const sample = JSON.parse(
  await readFile(
    new URL("../../../spaces/aigov-core-evidence-viewer/sample-evidence-export.json", import.meta.url),
    "utf8",
  ),
);
const sampleResult = await verifyHashChain(
  sample.evidence_hashes.log_chain,
  sample.evidence_hashes.chain_head_record_sha256,
);
assert.equal(sampleResult.ok, true, "the bundled sample evidence must verify");

const eventJson = JSON.stringify({ event_type: "run_started", event_id: "demo-1" });
const recordHash = createHash("sha256")
  .update(`GENESIS\n${eventJson}`, "utf8")
  .digest("hex");
const record = { prev_hash: "GENESIS", event_json: eventJson, record_hash: recordHash };

const valid = await verifyHashChain([record], recordHash);
assert.equal(valid.ok, true, valid.message);

const missingHead = await verifyHashChain([record], undefined);
assert.equal(missingHead.ok, false, "a missing declared chain head must fail");

const tampered = await verifyHashChain(
  [{ ...record, event_json: JSON.stringify({ event_type: "tampered" }) }],
  recordHash,
);
assert.equal(tampered.ok, false, "changed event JSON must fail the hash check");

const brokenLink = await verifyHashChain(
  [{ ...record, prev_hash: "0".repeat(64) }],
  recordHash,
);
assert.equal(brokenLink.ok, false, "a wrong genesis link must fail the chain check");

assert.equal((await verifyHashChain([null], recordHash)).ok, false, "malformed rows must fail closed");
assert.equal((await verifyHashChain([{}], recordHash)).ok, false, "missing hash fields must fail closed");
assert.equal((await verifyHashChain([], "not-a-sha256")).ok, false, "malformed heads must fail closed");
assert.equal(
  (await verifyHashChain(Array.from({ length: 5001 }, () => record), recordHash)).ok,
  false,
  "oversized chains must be rejected before hashing",
);

const tamperedSample = structuredClone(sample);
tamperedSample.evidence_hashes.log_chain[0].event_json =
  tamperedSample.evidence_hashes.log_chain[0].event_json.replace("evaluation_passed", "<script>");
assert.equal(
  (await verifyHashChain(
    tamperedSample.evidence_hashes.log_chain,
    tamperedSample.evidence_hashes.chain_head_record_sha256,
  )).ok,
  false,
  "HTML/script tampering in event content must not pass integrity verification",
);

console.log("Replay viewer hash-chain tests passed.");
