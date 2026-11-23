# `ci-core`

`ci-core` is a standalone, repository-external sandboxed check-execution,
content-addressed skipping, and keyless cryptographic attestation engine for
GitHub Actions (`github.com` Free/Pro/Team and GitHub Enterprise Cloud).

## Workspace Architecture

- **`crates/ci-core-model`** (`#![forbid(unsafe_code)]`, zero HTTP, async,
  process, or filesystem crates):
  - Validated opaque domain types (`RepoSlug`, `NonEmptyVec`, `Sha256Digest`,
    `GitOid`, `RepoRelPath`, `AbsUnixPath`, `CheckId`, `PinId`, `PinKey`,
    `LookupTag`, `ControlPlaneTransition`, and non-deserializable proof token
    `VerifiedClaim`).
  - Domain-separated RFC 8785 JCS SHA-256 digests (`TreeMerkle`,
    `ImageRecipeDigest`, `CacheKeyDigest`, `ActionDigest`).
  - Multi-hop POSIX symlink confinement validators (`validate_source_closure`
    and `validate_confined_dir`) and zero-execution static Cargo workspace
    closure discovery + dual static `cargo_locked` registry audit (`cargo_static`).
  - Offline Sigstore `Bundle0_3` verification (`sigstore-verify@0.16.0`) against
    compile-time embedded `PublicGood` and `GitHub` `TrustedRoot`s with
    transitive signer-provenance enforcement (`provenance_signers`).
  - Consumer TCB lattice (`EffectiveTcb`), `.github/CODEOWNERS` dominance and
    last-match-wins validator (`validate_codeowners`), sibling workflow
    anti-spoof validator (`validate_workflows`), two-step bare-Git `mergeQueue`
    commit-slice attribution, and compile-time-offline `evaluate_gate`.
- **`crates/ci-core-cli`** (`#![forbid(unsafe_code)]`):
  - Hardened bare-Git store (`BareGitTree`), `LocalWorktree`, and bare
    `git merge-tree --write-tree` commit-slice replay (`git_bare`).
  - Native OCI Distribution v2 GHCR client (`GhcrRegistry`) and pure OCI layout
    verifier (`verify_oci_layout`, `ghcr`).
  - Keyless batch DSSE signing (`sigstore-sign@0.16.0`) and bottom-up
    `msha256 -> isha256 -> ksha256 -> asha256` commit ordering (`signer`).
  - Hermetic Linux `Container` (`docker run --network=none --read-only --cap-drop=ALL`)
    and `NestedBwrap` (`bwrap --unshare-all --cap-drop ALL`) sandboxes, isolated-`cwd`
    `cargo fetch --locked` over 0-byte target stubs, and `O_NOFOLLOW` output and
    cache packing (`sandbox`).
- **`.github/workflows/`**:
  - `ci.yml` & `ci-pr.yml`: Least-privilege reusable workflows (`plan` ->
    `build-images` -> `execute` -> `publish` -> `gate` for trusted `merge_group`/
    `push` runs, and read-only `plan` -> `build-images` -> `execute` -> `gate`
    for `pull_request` runs; zero `actions: write`, zero `attestations: write`,
    zero `actions/checkout`).
  - `review-signal.yml` & `review-rerun.yml`: Two-stage zero-artifact fork-safe
    PR review rerun companion workflows.
  - `release.yml`: Two-phase static `musl` (`ci-core` + `bwrap`) release builder.
- **`examples/zerocopy/`**: Complete declarative onboarding specimen and
  Repository Ruleset configuration (`RULESETS.md`) covering `google/zerocopy`.

## CLI Subcommands

```bash
# Validate checks.toml, workflows, and .github/CODEOWNERS statically:
ci-core verify-repo --config ci/checks.toml --repo-root /path/to/repo

# Reproduce any check locally (Container / NestedBwrap, or unsandboxed --native):
ci-core run-local --config ci/checks.toml --repo-root /path/to/repo --check <check-id> [--native]

# Download and cryptographically verify a declared post-merge check output:
ci-core fetch-output --config ci/checks.toml --rev <40-hex-sha> --check <check-id> --output <name> --dest ./out

# Print live {m,i,a,k}sha256-* GHCR tags to retain during garbage collection:
ci-core plan --config ci/checks.toml --gc-keep
```

## Development & Verification

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
