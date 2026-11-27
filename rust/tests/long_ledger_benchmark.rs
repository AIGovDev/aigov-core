use aigov_audit::verify_chain::verify_chain;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use tempfile::tempdir;

const PAYLOAD_BYTES: usize = 256;
const DEFAULT_SIZES: &[usize] = &[1_000, 10_000, 100_000];
const DEFAULT_ITERATIONS: usize = 5;
const MAX_RECORDS: usize = 1_000_000;

#[derive(Serialize)]
struct StoredRecordLine<'a> {
    prev_hash: &'a str,
    record_hash: &'a str,
    event_json: &'a str,
}

fn record_hash(previous: &str, event_json: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(previous.as_bytes());
    hasher.update(b"\n");
    hasher.update(event_json.as_bytes());
    hex::encode(hasher.finalize())
}

fn write_ledger(path: &Path, record_count: usize) -> Vec<u64> {
    let file = File::create(path).expect("create synthetic ledger");
    let mut writer = BufWriter::new(file);
    let payload = "x".repeat(PAYLOAD_BYTES);
    let mut previous = "GENESIS".to_string();
    let mut hash_offsets = Vec::with_capacity(record_count);
    let mut file_offset = 0_u64;

    for index in 0..record_count {
        let event_json = json!({
            "event_id": format!("benchmark-{index:08}"),
            "event_type": "benchmark_event",
            "payload": payload,
        })
        .to_string();
        let hash = record_hash(&previous, &event_json);
        let line = serde_json::to_vec(&StoredRecordLine {
            prev_hash: &previous,
            record_hash: &hash,
            event_json: &event_json,
        })
        .expect("serialize stored record");
        let hash_offset = line
            .windows(hash.len())
            .position(|window| window == hash.as_bytes())
            .expect("record hash must occur in serialized record");
        hash_offsets.push(file_offset + hash_offset as u64);
        writer.write_all(&line).expect("write stored record");
        writer.write_all(b"\n").expect("terminate stored record");
        file_offset += line.len() as u64 + 1;
        previous = hash;
    }

    writer.flush().expect("flush synthetic ledger");
    hash_offsets
}

fn tamper_hash(path: &Path, offset: u64) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open ledger for controlled tampering");
    file.seek(SeekFrom::Start(offset))
        .expect("seek to record hash");
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte).expect("read original hash byte");
    byte[0] = if byte[0] == b'0' { b'1' } else { b'0' };
    file.seek(SeekFrom::Start(offset))
        .expect("seek back to record hash");
    file.write_all(&byte).expect("tamper one hash character");
    file.flush().expect("flush tampered ledger");
}

fn verify_expected(path: &Path, expected_valid: bool) -> u128 {
    let start = Instant::now();
    let result = verify_chain(path.to_str().expect("UTF-8 temporary path"));
    let elapsed_ns = start.elapsed().as_nanos();
    match (expected_valid, result) {
        (true, Ok(())) | (false, Err(_)) => elapsed_ns,
        (true, Err(error)) => panic!("valid synthetic ledger rejected: {error}"),
        (false, Ok(())) => panic!("tampered synthetic ledger was accepted"),
    }
}

fn file_sha256(path: &Path) -> String {
    let bytes = fs::read(path).expect("read generated ledger for digest");
    hex::encode(Sha256::digest(bytes))
}

fn parse_sizes() -> Vec<usize> {
    let raw = std::env::var("AIGOV_LEDGER_BENCHMARK_SIZES").ok();
    let sizes: Vec<usize> = raw
        .map(|value| {
            value
                .split(',')
                .map(|part| part.trim().parse().expect("sizes must be comma-separated integers"))
                .collect()
        })
        .unwrap_or_else(|| DEFAULT_SIZES.to_vec());
    assert!(!sizes.is_empty(), "at least one record count is required");
    assert!(
        sizes.iter().all(|size| (1..=MAX_RECORDS).contains(size)),
        "record counts must be between 1 and {MAX_RECORDS}"
    );
    sizes
}

fn parse_iterations() -> usize {
    let iterations = std::env::var("AIGOV_LEDGER_BENCHMARK_ITERATIONS")
        .ok()
        .map(|value| value.parse().expect("iterations must be an integer"))
        .unwrap_or(DEFAULT_ITERATIONS);
    assert!((1..=100).contains(&iterations), "iterations must be 1–100");
    iterations
}

fn median(values: &[u128]) -> u128 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        sorted[middle - 1] + (sorted[middle] - sorted[middle - 1]) / 2
    } else {
        sorted[middle]
    }
}

fn p95(values: &[u128]) -> u128 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let index = (sorted.len() * 95).div_ceil(100).saturating_sub(1);
    sorted[index]
}

#[test]
fn verifier_accepts_a_valid_chain_and_rejects_a_tampered_hash() {
    let directory = tempdir().expect("create test directory");
    let valid = directory.path().join("valid.jsonl");
    let offsets = write_ledger(&valid, 8);
    assert!(verify_chain(valid.to_str().unwrap()).is_ok());

    let tampered = directory.path().join("tampered.jsonl");
    fs::copy(&valid, &tampered).expect("copy test ledger");
    tamper_hash(&tampered, offsets[4]);
    assert!(verify_chain(tampered.to_str().unwrap()).is_err());
}

#[test]
#[ignore = "manual performance benchmark; timings are machine-specific"]
fn long_ledger_verification_benchmark() {
    let output = std::env::var_os("AIGOV_LEDGER_BENCHMARK_OUT")
        .map(PathBuf::from)
        .expect("set AIGOV_LEDGER_BENCHMARK_OUT to a JSON output path");
    let sizes = parse_sizes();
    let iterations = parse_iterations();
    let directory = tempdir().expect("create benchmark directory");
    let rustc = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|result| result.status.success())
        .map(|result| String::from_utf8_lossy(&result.stdout).trim().to_string());
    let mut measurements = Vec::new();

    for record_count in sizes.iter().copied() {
        let valid_path = directory.path().join(format!("valid-{record_count}.jsonl"));
        let hash_offsets = write_ledger(&valid_path, record_count);
        let ledger_bytes = fs::metadata(&valid_path).expect("ledger metadata").len();
        let dataset_sha256 = file_sha256(&valid_path);
        let corrupt_positions = [
            ("corrupt_first", 0),
            ("corrupt_middle", record_count / 2),
            ("corrupt_last", record_count - 1),
        ];

        for (scenario, corrupt_index) in std::iter::once(("valid", None))
            .chain(corrupt_positions.map(|(name, index)| (name, Some(index))))
        {
            let path = if let Some(index) = corrupt_index {
                let path = directory
                    .path()
                    .join(format!("{scenario}-{record_count}.jsonl"));
                fs::copy(&valid_path, &path).expect("copy benchmark ledger");
                tamper_hash(&path, hash_offsets[index]);
                path
            } else {
                valid_path.clone()
            };
            let expected_valid = corrupt_index.is_none();

            // One unrecorded pass warms the filesystem cache for this exact file.
            let _ = verify_expected(&path, expected_valid);
            let samples_ns: Vec<u128> = (0..iterations)
                .map(|_| verify_expected(&path, expected_valid))
                .collect();

            measurements.push(json!({
                "record_count": record_count,
                "ledger_bytes": ledger_bytes,
                "dataset_sha256": dataset_sha256,
                "scenario": scenario,
                "corrupt_record_index_zero_based": corrupt_index,
                "expected_valid": expected_valid,
                "verified_expected_result": true,
                "warmup_runs": 1,
                "iterations": iterations,
                "samples_ns": samples_ns,
                "median_ns": median(&samples_ns),
                "p95_ns_nearest_rank": p95(&samples_ns),
            }));
            if corrupt_index.is_some() {
                let _ = fs::remove_file(path);
            }
        }
    }

    let result = json!({
        "schema_version": 1,
        "benchmark": "aigov-core-long-ledger-verification",
        "revision": std::env::var("AIGOV_BENCHMARK_REVISION").ok(),
        "environment": {
            "os": std::env::consts::OS,
            "architecture": std::env::consts::ARCH,
            "rustc": rustc,
            "release_build": !cfg!(debug_assertions),
            "available_parallelism": std::thread::available_parallelism().ok().map(|n| n.get()),
            "cache_protocol": "one unrecorded warm-up per scenario; OS cache remains unmanaged",
        },
        "workload": {
            "record_counts": sizes,
            "payload_bytes": PAYLOAD_BYTES,
            "iterations_per_scenario": iterations,
            "scenarios": ["valid", "corrupt_first", "corrupt_middle", "corrupt_last"],
            "generation": "deterministic synthetic JSONL; Core record hash rule",
        },
        "measurements": measurements,
        "limitations": [
            "File-backed verifier only; excludes HTTP, PostgreSQL, concurrent writers, and fsync durability.",
            "Synthetic records and one warm-up do not represent production traffic or cold-cache performance.",
            "No product comparison is included because equivalent workloads and semantics are not available.",
        ],
    });

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).expect("create result directory");
    }
    fs::write(&output, serde_json::to_vec_pretty(&result).expect("serialize benchmark result"))
        .expect("write benchmark result JSON");
    println!("ledger verification benchmark results: {}", output.display());
}
