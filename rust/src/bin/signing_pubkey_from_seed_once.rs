//! Tiny offline helper: print the base64 Ed25519 verifying key for a seed.
//! Usage: `signing_pubkey_from_seed_once <seed-hex-32-bytes>`
use aigov_audit::audit_export_signing::verifying_key_from_seed;
use base64::Engine;

fn main() {
    let s = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: signing_pubkey_from_seed_once <seed-hex-32-bytes>");
        std::process::exit(2);
    });
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect();
    let seed: [u8; 32] = bytes.try_into().expect("32 bytes");
    let vk = verifying_key_from_seed(&seed);
    println!(
        "{}",
        base64::engine::general_purpose::STANDARD.encode(vk.to_bytes())
    );
}
