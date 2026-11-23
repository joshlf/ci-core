//! Domain-separated RFC 8785 JCS SHA-256 preimages and canonical digests.
//!
//! All digests hash canonical JSON (`serde_json_canonicalizer::to_vec`) with an
//! explicit `"domain"` discriminator, excluding wall-clock timestamps, runner
//! labels, storage tiers, commit SHAs, `$GITHUB_REPOSITORY`, `.git` remotes,
//! and control-plane policy fields.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::types::{
    AbsUnixPath, CacheScope, CacheSlotId, CheckId, Claim, OutputName, PinId, PinKey, Platform,
    RegistryIndexUrl, RepoRelPath, SandboxMode, Sha256Digest, pin_env_var_name,
};

/// Serializes `value` using RFC 8785 JSON Canonicalization Scheme (JCS).
pub fn to_jcs_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json_canonicalizer::to_vec(value).map_err(|e| format!("JCS canonicalization failed: {e}"))
}

/// Serializes `Claim` as canonical JCS bytes and returns `(bytes, sha256)`.
pub fn canonicalize_claim(claim: &Claim) -> Result<(Vec<u8>, Sha256Digest), String> {
    let bytes = to_jcs_bytes(claim)?;
    let digest = Sha256Digest::hash_bytes(&bytes);
    Ok((bytes, digest))
}

/// Entry hashed inside a `TreeMerkle` closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MerkleEntry {
    /// Regular file hashed by exact content SHA-256 and `0o100` executable bit.
    Regular {
        /// Whether the `0o100` executable permission bit is set.
        executable: bool,
        /// SHA-256 digest of the file bytes.
        sha256: Sha256Digest,
    },
    /// Validated in-closure relative symbolic link target.
    Symlink {
        /// Raw POSIX relative symlink target string.
        target: String,
    },
}

#[derive(Serialize)]
struct TreeMerkleDoc<'a> {
    domain: &'static str,
    entries: &'a BTreeMap<RepoRelPath, MerkleEntry>,
}

/// Computes `TreeMerkle` (`"ci-core/v1/tree-merkle"`) over a validated closure.
pub fn compute_tree_merkle(entries: &BTreeMap<RepoRelPath, MerkleEntry>) -> Sha256Digest {
    let doc = TreeMerkleDoc {
        domain: "ci-core/v1/tree-merkle",
        entries,
    };
    let bytes = serde_json_canonicalizer::to_vec(&doc)
        .expect("TreeMerkleDoc contains only infallible string/bool/map types");
    Sha256Digest::hash_bytes(&bytes)
}

/// Canonical preimage for `ImageRecipeDigest` (`"ci-core/v1/image-recipe"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRecipePreimage {
    /// Domain separator (`"ci-core/v1/image-recipe"`).
    pub domain: String,
    /// Repository-relative Dockerfile path.
    pub dockerfile: RepoRelPath,
    /// SHA-256 of the Dockerfile bytes.
    pub dockerfile_sha256: Sha256Digest,
    /// `TreeMerkle` of the build context closure (including `dockerfile`).
    pub context_merkle: Sha256Digest,
    /// Explicit Docker `--build-arg` map.
    pub build_args: BTreeMap<String, String>,
    /// Structured validated pin key/values injected as `PIN_<PIN>__<KEY>`.
    pub pins: BTreeMap<PinId, BTreeMap<PinKey, String>>,
    /// Target container platform (`linux/amd64` or `linux/arm64`).
    pub platform: Platform,
    /// `https://github.com/<cfg.repo.slug.canonical()>` baked into OCI label.
    pub source_repo_label: String,
}

impl ImageRecipePreimage {
    /// Constructs a new `ImageRecipePreimage` with the v1 domain tag.
    pub fn new(
        dockerfile: RepoRelPath,
        dockerfile_sha256: Sha256Digest,
        context_merkle: Sha256Digest,
        build_args: BTreeMap<String, String>,
        pins: BTreeMap<PinId, BTreeMap<PinKey, String>>,
        platform: Platform,
        source_repo_label: String,
    ) -> Self {
        Self {
            domain: "ci-core/v1/image-recipe".to_owned(),
            dockerfile,
            dockerfile_sha256,
            context_merkle,
            build_args,
            pins,
            platform,
            source_repo_label,
        }
    }

    /// Hashes this preimage into `ImageRecipeDigest`.
    pub fn digest(&self) -> Sha256Digest {
        let bytes =
            serde_json_canonicalizer::to_vec(self).expect("ImageRecipePreimage JCS is infallible");
        Sha256Digest::hash_bytes(&bytes)
    }

    /// Projects explicit `build_args` followed by `PIN_<NORM_PIN>__<NORM_KEY>`
    /// arguments in deterministic `BTreeMap` order for container image builds.
    pub fn projected_build_args(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (bk, bv) in &self.build_args {
            out.push((bk.clone(), bv.clone()));
        }
        for (pid, pmap) in &self.pins {
            for (pkey, pval) in pmap {
                out.push((pin_env_var_name(pid, pkey), pval.clone()));
            }
        }
        out
    }
}

/// Canonical `cargo_locked` specification bound inside `CacheKeyPreimage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CargoLockedDigestSpec {
    /// Workspace `Cargo.toml` path.
    pub workspace: RepoRelPath,
    /// Allowlisted registry index URLs keyed by Cargo registry name.
    pub allowed_registries: BTreeMap<String, RegistryIndexUrl>,
}

/// Image-independent portion of a cache key frozen during `plan` even when the
/// check's image is `ImagePlan::PendingBuild`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheKeyPreimage {
    /// Cache slot identifier.
    pub slot: CacheSlotId,
    /// `PerImage` or `CrossImage` binding rule.
    pub scope: CacheScope,
    /// `TreeMerkle` of declared cache input files (including `Cargo.lock` when
    /// `cargo_locked` is enabled).
    pub inputs_merkle: Sha256Digest,
    /// Selected check `env` entries listed in `caches.<slot>.env_keys`.
    pub env: BTreeMap<String, String>,
    /// Optional `cargo_locked` configuration (`None` on ordinary cache slots).
    pub cargo_locked: Option<CargoLockedDigestSpec>,
}

impl Ord for CargoLockedDigestSpec {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (&self.workspace, &self.allowed_registries)
            .cmp(&(&other.workspace, &other.allowed_registries))
    }
}

impl PartialOrd for CargoLockedDigestSpec {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Serialize)]
struct CacheKeyDoc<'a> {
    domain: &'static str,
    slot: &'a CacheSlotId,
    scope: CacheScope,
    image_manifest: Option<String>,
    inputs_merkle: &'a Sha256Digest,
    env: &'a BTreeMap<String, String>,
    cargo_locked: &'a Option<CargoLockedDigestSpec>,
}

impl CacheKeyPreimage {
    /// Finalizes `CacheKeyDigest` (`"ci-core/v1/cache-key"`), binding
    /// `Some(M)` when `scope == PerImage` and `None` when `scope == CrossImage`.
    pub fn finalize(
        &self,
        resolved_image_manifest: Option<&Sha256Digest>,
    ) -> Result<Sha256Digest, String> {
        let image_manifest = match self.scope {
            CacheScope::PerImage => {
                let m = resolved_image_manifest.ok_or_else(|| {
                    format!(
                        "per_image cache slot `{}` requires a resolved image manifest digest",
                        self.slot
                    )
                })?;
                Some(m.to_oci_digest())
            }
            CacheScope::CrossImage => None,
        };
        let doc = CacheKeyDoc {
            domain: "ci-core/v1/cache-key",
            slot: &self.slot,
            scope: self.scope,
            image_manifest,
            inputs_merkle: &self.inputs_merkle,
            env: &self.env,
            cargo_locked: &self.cargo_locked,
        };
        let bytes = serde_json_canonicalizer::to_vec(&doc).expect("CacheKeyDoc JCS is infallible");
        Ok(Sha256Digest::hash_bytes(&bytes))
    }
}

/// Cache mount topology entry bound inside `ActionPreimage`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheMountBinding {
    /// Mounted cache slot identifier.
    pub slot: CacheSlotId,
    /// Container mount path (`/cargo-home`, `/ci-cache/miri`, etc.).
    pub mount: AbsUnixPath,
}

/// Image-manifest-parameterized check action preimage frozen during `plan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionPreimage {
    /// Matrix-expanded check identifier.
    pub check_id: CheckId,
    /// `TreeMerkle` of the check's validated source closure.
    pub source_merkle: Sha256Digest,
    /// Target container platform.
    pub platform: Platform,
    /// Sandbox topology (`Container` or `NestedBwrap`).
    pub sandbox: SandboxMode,
    /// Sorted prefix-free empty writable overlay directories inside `/work`.
    pub writable_dirs: Vec<RepoRelPath>,
    /// Optional working directory beneath `/work`.
    pub workdir: Option<RepoRelPath>,
    /// Direct `execve` argument vector (`--entrypoint ""`).
    pub command: Vec<String>,
    /// Interpolated check environment variables.
    pub env: BTreeMap<String, String>,
    /// Structured validated data pins bound to this check.
    pub pins: BTreeMap<PinId, BTreeMap<PinKey, String>>,
    /// Sorted mounted cache slot bindings.
    pub cache_mounts: Vec<CacheMountBinding>,
    /// Sorted declared output filenames.
    pub declared_outputs: Vec<OutputName>,
}

#[derive(Serialize)]
struct ActionDoc<'a> {
    domain: &'static str,
    check_id: &'a CheckId,
    source_merkle: &'a Sha256Digest,
    image_manifest: String,
    platform: Platform,
    sandbox: SandboxMode,
    writable_dirs: &'a [RepoRelPath],
    workdir: &'a Option<RepoRelPath>,
    command: &'a [String],
    env: &'a BTreeMap<String, String>,
    pins: &'a BTreeMap<PinId, BTreeMap<PinKey, String>>,
    cache_mounts: &'a [CacheMountBinding],
    declared_outputs: &'a [OutputName],
}

impl ActionPreimage {
    /// Finalizes `ActionDigest` (`"ci-core/v1/action"`) once the check's
    /// single-platform OCI image manifest digest `M` is known.
    pub fn finalize(&self, image_manifest: &Sha256Digest) -> Sha256Digest {
        let doc = ActionDoc {
            domain: "ci-core/v1/action",
            check_id: &self.check_id,
            source_merkle: &self.source_merkle,
            image_manifest: image_manifest.to_oci_digest(),
            platform: self.platform,
            sandbox: self.sandbox,
            writable_dirs: &self.writable_dirs,
            workdir: &self.workdir,
            command: &self.command,
            env: &self.env,
            pins: &self.pins,
            cache_mounts: &self.cache_mounts,
            declared_outputs: &self.declared_outputs,
        };
        let bytes = serde_json_canonicalizer::to_vec(&doc).expect("ActionDoc JCS is infallible");
        Sha256Digest::hash_bytes(&bytes)
    }
}
