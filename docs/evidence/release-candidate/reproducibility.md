# Reproducibility of the Core release binary (measured)

Source: the same commit, built twice with `cargo build --release --locked --bin aigov_audit` on the test workstation (macOS, Apple silicon, one
toolchain). Both builds used the lockfile.

| Build | Target directory | SHA-256 |
|---|---|---|
| A (repository build, incremental after the last source change) | `rust/target` | `b4e44881d8579ca7e6fde583291a402efe65fbf1acf751f03c19c124acee8f02` |
| B (clean build, every dependency compiled) | a separate directory outside the repository | `6392bf0a31b83157c04d5c205be2160d651245879f1a34d1a13f413d1da8c53e` |

Result: **not byte-identical.** Both files are 14,832,368 bytes. They differ at 48 bytes, in two places (offsets 2025–2040 and 14717361–14717392).
The differing values are 16-byte identifiers that look like hash-derived identities of crates and items. The code is the same; no build path is
embedded in either file.

Earlier, on the same workstation, rebuilding only the Core crate in the same target directory gave the same hash twice (`1dea2793…`). That shows the crate
itself is deterministic when its dependencies are fixed. It does not show that a clean build with a different target layout gives the same identifiers.

What this means for a release: a byte-identical rebuild needs the same target-directory layout and toolchain. Neither is recorded by the current build
instructions. Until they are, the release record names the binary's hash, and a reviewer can check it against the artifact that was built, not against a
rebuild. This is stated as residual R-10.

Not run: a rebuild in an independent, clean builder (a container or a separate machine). That is the test that would show whether the identifiers depend on
the machine.
