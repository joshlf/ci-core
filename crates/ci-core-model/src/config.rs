//! Strict `checks.toml` schema parser (`#[serde(deny_unknown_fields)]`),
//! forward-compatible `ControlPlaneHeader` projection, static `matrix` and
//! `matrix_exclude` expansion, pin file validation, and tree-bound closure
//! checks.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cargo_static::{
    CargoStaticError, StaticWorkspaceDiscovery, audit_cargo_locked, discover_workspace,
    expand_cargo_standard_paths,
};
use crate::digest::{
    ActionPreimage, CacheKeyPreimage, CacheMountBinding, CargoLockedDigestSpec, ImageRecipePreimage,
};
use crate::store::StoreTier;
use crate::tree::{
    SourceTree, TreeEntry, TreeError, ValidatedSourceClosure, compile_selector_glob,
    filter_paths_by_globs, validate_source_closure,
};
use crate::types::{
    AbsUnixPath, CacheScope, CacheSlotId, CallerMode, CheckId, CodeOwnerPrincipal,
    ControlPlanePolicy, GitOid, ImageId, NonEmptyVec, OutputName, PinId, PinKey, Platform,
    RegistryIndexUrl, RepoRelPath, RepoSlug, SandboxMode, Sha256Digest, SignerPolicy, SigstoreRoot,
    TriggerEvent, TypeError, WorkflowUri, is_valid_git_branch_name, pin_env_var_name,
};

const DEFAULT_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
const DEFAULT_PIN_MAX_BYTES: u64 = 65_536;
const DEFAULT_CACHE_MAX_BYTES: u64 = 2_147_483_648;
const RESERVED_ENV_EXACT: [&str; 4] = ["HOME", "TMPDIR", "LD_PRELOAD", "BASH_ENV"];
const RESERVED_ENV_PREFIXES: [&str; 3] = ["GITHUB_", "ACTIONS_", "RUNNER_"];
const RESERVED_SANDBOX_MOUNTS: [&str; 6] =
    ["/dev", "/proc", "/tmp", "/work", "/scratch", "/outputs"];

/// Errors produced when parsing or validating `checks.toml` or `[pins.*]` files.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// TOML syntax or `#[serde(deny_unknown_fields)]` failure.
    #[error("checks.toml parse error: {0}")]
    Toml(String),
    /// Refined domain-type error.
    #[error(transparent)]
    Type(#[from] TypeError),
    /// Unsupported `schema_version`.
    #[error("unsupported schema_version {0} (expected 1)")]
    UnsupportedSchemaVersion(u32),
    /// Semantic schema invariant violation.
    #[error("config validation error: {0}")]
    Validation(String),
    /// Static Cargo workspace or `cargo_locked` error.
    #[error(transparent)]
    Cargo(#[from] CargoStaticError),
    /// Source-tree or closure confinement error.
    #[error(transparent)]
    Tree(#[from] TreeError),
    /// Data-pin file validation failure (used by `tcb.rs` to escalate invalid
    /// pins to `ExecutableTcb`).
    #[error("pin `{pin}` at `{path}` failed validation: {reason}")]
    InvalidPinFile {
        /// Pin identifier.
        pin: PinId,
        /// Repository-relative pin TOML path.
        path: RepoRelPath,
        /// Validation failure reason.
        reason: String,
    },
}

/// Uniform path selector shared across `images.*.context`, `caches.*.inputs`,
/// and `checks[].inputs`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InputSelector {
    /// POSIX path globs (`include` minus `exclude`).
    Glob {
        /// Non-empty list of include globs.
        include: NonEmptyVec<String>,
        /// Optional exclude globs.
        #[serde(default)]
        exclude: Vec<String>,
    },
    /// Zero-execution static Cargo workspace closure (`CargoStandardPaths`).
    CargoWorkspace {
        /// Workspace or crate `Cargo.toml` path.
        manifest_path: RepoRelPath,
        /// Optional exclude globs applied after `CargoStandardPaths` expansion.
        #[serde(default)]
        exclude: Vec<String>,
    },
}

/// Raw `[repo]` section in `checks.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoConfig {
    /// Canonical `<Owner>/<Repo>` slug.
    pub slug: RepoSlug,
    /// Numeric GitHub repository ID (`.1.15`).
    pub id: u64,
    /// Numeric GitHub repository owner ID (`.1.17`).
    pub owner_id: u64,
    /// Protected default branch name (e.g. `"main"`).
    pub default_branch: String,
    /// Embedded Sigstore instance (`public_good` default or `github`).
    #[serde(default)]
    pub sigstore: SigstoreRoot,
    /// Expected OIDC issuer URL (`.1.8`).
    #[serde(default = "default_oidc_issuer")]
    pub oidc_issuer: String,
    /// Reusable engine workflow URI (`<org>/<repo>/.github/workflows/ci.yml`).
    pub trusted_engine_workflow: WorkflowUri,
    /// Optional explicit read-only PR reusable workflow URI (`ci-pr.yml` default).
    #[serde(default)]
    pub trusted_pr_workflow: Option<WorkflowUri>,
    /// Optional explicit reusable Stage-1 review signal workflow URI.
    #[serde(default)]
    pub trusted_review_signal_workflow: Option<WorkflowUri>,
    /// Optional explicit reusable Stage-2 review rerun workflow URI.
    #[serde(default)]
    pub trusted_review_rerun_workflow: Option<WorkflowUri>,
    /// Allowlisted 40-hex engine commit SHAs.
    pub trusted_engine_shas: NonEmptyVec<GitOid>,
    /// Optional override for `ghcr.io/<lower_slug>/ci-cas`.
    #[serde(default)]
    pub cas_repo: Option<String>,
    /// Optional override for `ghcr.io/<lower_slug>/ci-cache`.
    #[serde(default)]
    pub cache_repo: Option<String>,
}

fn default_oidc_issuer() -> String {
    DEFAULT_OIDC_ISSUER.to_owned()
}

impl RepoConfig {
    /// Resolved public CAS repository URI.
    pub fn effective_cas_repo(&self) -> String {
        self.cas_repo
            .clone()
            .unwrap_or_else(|| self.slug.default_cas_repo())
    }

    /// Resolved private cache repository URI.
    pub fn effective_cache_repo(&self) -> String {
        self.cache_repo
            .clone()
            .unwrap_or_else(|| self.slug.default_cache_repo())
    }

    /// Resolved read-only PR reusable workflow (`ci-pr.yml`) URI.
    pub fn effective_pr_workflow_uri(&self) -> Result<WorkflowUri, TypeError> {
        match &self.trusted_pr_workflow {
            Some(u) => Ok(u.clone()),
            None => self.trusted_engine_workflow.with_workflow_file("ci-pr.yml"),
        }
    }

    /// Resolved reusable Stage-1 `review-signal.yml` URI.
    pub fn effective_review_signal_uri(&self) -> Result<WorkflowUri, TypeError> {
        match &self.trusted_review_signal_workflow {
            Some(u) => Ok(u.clone()),
            None => self
                .trusted_engine_workflow
                .with_workflow_file("review-signal.yml"),
        }
    }

    /// Resolved reusable Stage-2 `review-rerun.yml` URI.
    pub fn effective_review_rerun_uri(&self) -> Result<WorkflowUri, TypeError> {
        match &self.trusted_review_rerun_workflow {
            Some(u) => Ok(u.clone()),
            None => self
                .trusted_engine_workflow
                .with_workflow_file("review-rerun.yml"),
        }
    }

    /// Returns `true` iff both `[repo]` blocks bind the identical repository
    /// identity (`slug`, `id`, `owner_id`, and `default_branch`).
    pub fn same_identity(&self, other: &Self) -> bool {
        self.slug == other.slug
            && self.id == other.id
            && self.owner_id == other.owner_id
            && self.default_branch == other.default_branch
    }

    /// Projects `[repo]` into a `SignerPolicy`.
    pub fn signer_policy(&self) -> Result<SignerPolicy, TypeError> {
        Ok(SignerPolicy {
            repo_id: self.id,
            owner_id: self.owner_id,
            default_branch: self.default_branch.clone(),
            oidc_issuer: self.oidc_issuer.clone(),
            sigstore: self.sigstore,
            trusted_engine_workflow: self.trusted_engine_workflow.clone(),
            trusted_pr_workflow: self.effective_pr_workflow_uri()?,
            trusted_review_signal_workflow: self.effective_review_signal_uri()?,
            trusted_review_rerun_workflow: self.effective_review_rerun_uri()?,
            trusted_engine_shas: self.trusted_engine_shas.clone(),
        })
    }
}

fn default_review_signal_wf() -> RepoRelPath {
    RepoRelPath::new(".github/workflows/ci-review-signal.yml").expect("static")
}

fn default_review_rerun_wf() -> RepoRelPath {
    RepoRelPath::new(".github/workflows/ci-review-rerun.yml").expect("static")
}

fn default_caller_workflows() -> NonEmptyVec<RepoRelPath> {
    NonEmptyVec::singleton(RepoRelPath::new(".github/workflows/ci.yml").expect("static"))
}

fn default_repo_gate_check_name() -> String {
    "ci / gate".to_owned()
}

fn default_org_gate_check_name() -> String {
    "gate".to_owned()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RawCallerMode {
    RepoRuleset {
        #[serde(default = "default_caller_workflows")]
        caller_workflows: NonEmptyVec<RepoRelPath>,
        #[serde(default = "default_repo_gate_check_name")]
        gate_check_name: String,
        codeowners: NonEmptyVec<CodeOwnerPrincipal>,
    },
    OrgRuleset {
        required_workflow_ids: NonEmptyVec<u64>,
        #[serde(default)]
        push_caller_workflow: Option<RepoRelPath>,
        #[serde(default = "default_org_gate_check_name")]
        gate_check_name: String,
    },
}

impl From<RawCallerMode> for CallerMode {
    fn from(raw: RawCallerMode) -> Self {
        match raw {
            RawCallerMode::RepoRuleset {
                caller_workflows,
                gate_check_name,
                codeowners,
            } => Self::RepoRuleset {
                caller_workflows,
                gate_check_name,
                codeowners,
            },
            RawCallerMode::OrgRuleset {
                required_workflow_ids,
                push_caller_workflow,
                gate_check_name,
            } => Self::OrgRuleset {
                required_workflow_ids,
                push_caller_workflow,
                gate_check_name,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTcbConfig {
    owner_user_ids: NonEmptyVec<u64>,
    #[serde(default)]
    allow_owner_self_approval: bool,
    #[serde(default = "default_review_signal_wf")]
    review_signal_workflow: RepoRelPath,
    #[serde(default = "default_review_rerun_wf")]
    review_rerun_workflow: RepoRelPath,
    #[serde(default)]
    non_tcb_workflows: Vec<String>,
    #[serde(default)]
    non_tcb_subtrees: Vec<RepoRelPath>,
    #[serde(default)]
    extra_executable_paths: Vec<String>,
    caller: RawCallerMode,
}

/// Validated `[tcb]` configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbConfig {
    /// Pinned numeric GitHub user IDs authorized to approve TCB and pin PRs.
    pub owner_user_ids: NonEmptyVec<u64>,
    /// Enables `/ci-core approve <oid>` on solo-owner personal repositories.
    pub allow_owner_self_approval: bool,
    /// Hoisted consumer Stage-1 review signal workflow path.
    pub review_signal_workflow: RepoRelPath,
    /// Hoisted consumer Stage-2 review rerun workflow path.
    pub review_rerun_workflow: RepoRelPath,
    /// Read-only / SARIF-only workflow basenames under `.github/workflows/`.
    pub non_tcb_workflows: Vec<String>,
    /// Exempted fixture/vendored subtrees (`evals`, `skills`, `zerocopy/vendor`).
    pub non_tcb_subtrees: Vec<RepoRelPath>,
    /// Extra executable TCB globs (`ci/scripts/**`, etc.).
    pub extra_executable_paths: Vec<String>,
    /// Caller authorization mode (`RepoRuleset` or `OrgRuleset`).
    pub caller: CallerMode,
}

fn default_pin_max_bytes() -> u64 {
    DEFAULT_PIN_MAX_BYTES
}

/// Validated `[pins.<PinId>]` specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinSpec {
    /// Repository-relative flat TOML file path (`100644`, non-symlink).
    pub path: RepoRelPath,
    /// Maximum allowed file size in bytes (`65_536` default).
    #[serde(default = "default_pin_max_bytes")]
    pub max_bytes: u64,
    /// Declared keys mapped to unanchored regex patterns (wrapped in `\A(?:...)\z`).
    pub keys: BTreeMap<PinKey, String>,
}

fn default_platform() -> Platform {
    Platform::LinuxAmd64
}

/// Validated `[images.<ImageId>]` specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSpec {
    /// Repository-relative Dockerfile path (unconditionally included in context).
    pub dockerfile: RepoRelPath,
    /// Additional context selectors.
    #[serde(default)]
    pub context: Vec<InputSelector>,
    /// Referenced `[pins.*]` tables injected as `--build-arg PIN_<P>__<K>=<V>`.
    #[serde(default)]
    pub pins: Vec<PinId>,
    /// Explicit Docker `--build-arg` entries.
    #[serde(default)]
    pub build_args: BTreeMap<String, String>,
    /// Target container platform (`linux/amd64` default).
    #[serde(default = "default_platform")]
    pub platform: Platform,
    /// GitHub Actions runner label (e.g. `"ubuntu-24.04"`).
    pub runner: String,
}

fn default_allowed_registries() -> BTreeMap<String, RegistryIndexUrl> {
    let mut map = BTreeMap::new();
    map.insert(
        "crates-io".to_owned(),
        RegistryIndexUrl::new(RegistryIndexUrl::CRATES_IO).expect("static"),
    );
    map
}

/// Pre-sandbox `cargo fetch --locked` configuration on a cache slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CargoLockedConfig {
    /// Workspace `Cargo.toml` path.
    pub workspace: RepoRelPath,
    /// Allowlisted HTTPS registry index URLs (defaults to `crates-io` only).
    #[serde(default = "default_allowed_registries")]
    pub allowed_registries: BTreeMap<String, RegistryIndexUrl>,
}

impl CargoLockedConfig {
    /// Converts into canonical `CargoLockedDigestSpec`.
    pub fn to_digest_spec(&self) -> CargoLockedDigestSpec {
        CargoLockedDigestSpec {
            workspace: self.workspace.clone(),
            allowed_registries: self.allowed_registries.clone(),
        }
    }
}

fn default_cache_max_bytes() -> u64 {
    DEFAULT_CACHE_MAX_BYTES
}

/// Validated `[caches.<CacheSlotId>]` specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheSpec {
    /// Absolute sandbox mount path (`/cargo-home`, `/ci-cache/miri`, etc.).
    pub mount: AbsUnixPath,
    /// Image-binding scope (`PerImage` default or `CrossImage`).
    #[serde(default)]
    pub scope: CacheScope,
    /// Storage routing tier (`PrivateCache` default or opt-in `PublicCas`).
    #[serde(default)]
    pub tier: StoreTier,
    /// Cache key input selectors.
    #[serde(default)]
    pub inputs: Vec<InputSelector>,
    /// Check `env` variable names folded into `CacheKeyPreimage.env`.
    #[serde(default)]
    pub env_keys: Vec<String>,
    /// Maximum `.tar.zst` archive size in bytes (`2 GiB` default).
    #[serde(default = "default_cache_max_bytes")]
    pub max_bytes: u64,
    /// Optional safe pre-sandbox `cargo fetch --locked` populator.
    #[serde(default)]
    pub cargo_locked: Option<CargoLockedConfig>,
}

/// Declared check output file specification (`outputs = [{ name, max_bytes }]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredOutputSpec {
    /// Output filename inside `/outputs`.
    pub name: OutputName,
    /// Maximum allowed file size in bytes.
    pub max_bytes: u64,
}

fn default_sandbox_mode() -> SandboxMode {
    SandboxMode::Container
}

fn default_events() -> NonEmptyVec<TriggerEvent> {
    NonEmptyVec::new(vec![
        TriggerEvent::PullRequest,
        TriggerEvent::MergeGroup,
        TriggerEvent::Push,
    ])
    .expect("non-empty static")
}

/// Optional commit-message policy evaluated outside check sandboxes against
/// commits introduced by the event (`base_sha..pr_head_sha` on `pull_request`,
/// `base_sha..event_sha` first-parent commits on `merge_group`, and `event_sha`
/// on `push`), excluded from all content-addressed digests.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitPolicyConfig {
    /// Optional unanchored Rust regex that must not match any commit message in
    /// the evaluated commit range.
    #[serde(default)]
    pub forbid_message_regex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCheckEntry {
    id: CheckId,
    image: String,
    #[serde(default = "default_sandbox_mode")]
    sandbox: SandboxMode,
    #[serde(default)]
    writable_dirs: Vec<RepoRelPath>,
    runner: String,
    #[serde(default)]
    shard_group: Option<String>,
    #[serde(default)]
    workdir: Option<String>,
    #[serde(default)]
    pins: Vec<PinId>,
    inputs: NonEmptyVec<InputSelector>,
    command: NonEmptyVec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    matrix: BTreeMap<String, NonEmptyVec<String>>,
    #[serde(default)]
    matrix_exclude: Vec<BTreeMap<String, String>>,
    #[serde(default = "default_events")]
    events: NonEmptyVec<TriggerEvent>,
    #[serde(default)]
    caches: Vec<String>,
    #[serde(default)]
    outputs: Vec<DeclaredOutputSpec>,
    #[serde(default)]
    max_age_days: Option<NonZeroU32>,
}

/// Concrete matrix-expanded check specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckSpec {
    /// Matrix-expanded check identifier (`<= 240` chars).
    pub id: CheckId,
    /// Referenced `[images.<ImageId>]`.
    pub image: ImageId,
    /// Hermetic sandbox mode (`Container` or `NestedBwrap`).
    pub sandbox: SandboxMode,
    /// Sorted prefix-free writable overlay directories beneath `/work`.
    pub writable_dirs: Vec<RepoRelPath>,
    /// GitHub Actions runner label.
    pub runner: String,
    /// Optional shard co-location key within `(runner, sandbox, image)` (excluded
    /// from `ActionDigest`).
    pub shard_group: Option<String>,
    /// Optional working directory beneath `/work`.
    pub workdir: Option<RepoRelPath>,
    /// Referenced `[pins.<PinId>]` tables.
    pub pins: Vec<PinId>,
    /// Source closure selectors.
    pub inputs: NonEmptyVec<InputSelector>,
    /// Direct `execve` argument vector.
    pub command: NonEmptyVec<String>,
    /// Interpolated environment map.
    pub env: BTreeMap<String, String>,
    /// Trigger events on which this check is required.
    pub events: NonEmptyVec<TriggerEvent>,
    /// Mounted `[caches.<CacheSlotId>]` slots.
    pub caches: Vec<CacheSlotId>,
    /// Declared output specifications keyed by `OutputName`.
    pub outputs: BTreeMap<OutputName, DeclaredOutputSpec>,
    /// Optional recertification window in days (`None` = timeless reuse).
    pub max_age_days: Option<NonZeroU32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawChecksToml {
    schema_version: u32,
    repo: RepoConfig,
    tcb: RawTcbConfig,
    #[serde(default)]
    commit_policy: CommitPolicyConfig,
    #[serde(default)]
    pins: BTreeMap<PinId, PinSpec>,
    #[serde(default)]
    images: BTreeMap<ImageId, ImageSpec>,
    #[serde(default)]
    caches: BTreeMap<CacheSlotId, CacheSpec>,
    #[serde(default)]
    checks: Vec<RawCheckEntry>,
}

/// Validated `checks.toml` configuration with all matrices expanded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksConfig {
    /// Schema version (`1`).
    pub schema_version: u32,
    /// `[repo]` identity and Sigstore/engine policy.
    pub repo: RepoConfig,
    /// `[tcb]` owner, workflow, subtree, and caller policy.
    pub tcb: TcbConfig,
    /// Optional `[commit_policy]` evaluated over VCS commit messages.
    pub commit_policy: CommitPolicyConfig,
    /// `[pins.*]` specifications.
    pub pins: BTreeMap<PinId, PinSpec>,
    /// `[images.*]` specifications.
    pub images: BTreeMap<ImageId, ImageSpec>,
    /// `[caches.*]` specifications.
    pub caches: BTreeMap<CacheSlotId, CacheSpec>,
    /// All matrix-expanded check specifications keyed by `CheckId` (prior to
    /// `events` filtering).
    pub checks: BTreeMap<CheckId, CheckSpec>,
}

/// Forward-compatible `[repo]` + `[tcb]` header parser used by `review-rerun`
/// so 1-PR engine + schema upgrades introducing new fields inside `[[checks]]`,
/// `[images]`, `[caches]`, or `[pins]` still extract `candidate_cp` cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPlaneHeader {
    /// Parsed `[repo]` block.
    pub repo: RepoConfig,
    /// Parsed `[tcb]` block.
    pub tcb: TcbConfig,
}

#[derive(Deserialize)]
struct LooseChecksHeader {
    schema_version: Option<u32>,
    repo: RepoConfig,
    tcb: RawTcbConfig,
}

impl ControlPlaneHeader {
    /// Parses `[repo]` and `[tcb]` while ignoring unknown sibling tables or
    /// fields in `[[checks]]`, `[images]`, `[caches]`, or `[pins]`.
    pub fn parse_toml(toml_str: &str) -> Result<Self, ConfigError> {
        let raw: LooseChecksHeader =
            toml::from_str(toml_str).map_err(|e| ConfigError::Toml(e.to_string()))?;
        let _ = raw.schema_version;
        let tcb = validate_tcb_block(&raw.repo, raw.tcb)?;
        validate_repo_block(&raw.repo)?;
        Ok(Self {
            repo: raw.repo,
            tcb,
        })
    }

    /// Projects this header into a `ControlPlanePolicy`.
    pub fn control_plane(&self) -> Result<ControlPlanePolicy, TypeError> {
        Ok(ControlPlanePolicy {
            signer: self.repo.signer_policy()?,
            caller: self.tcb.caller.clone(),
        })
    }
}

fn is_workflow_dir_yaml(path: &RepoRelPath) -> bool {
    let Some(rest) = path.as_str().strip_prefix(".github/workflows/") else {
        return false;
    };
    !rest.contains('/') && (rest.ends_with(".yml") || rest.ends_with(".yaml"))
}

fn validate_caller_prefix(prefix: &str) -> Result<(), ConfigError> {
    if prefix.is_empty()
        || prefix.trim() != prefix
        || prefix.contains('/')
        || prefix.contains("${{")
        || prefix.chars().any(char::is_control)
    {
        return Err(ConfigError::Validation(format!(
            "invalid gate_check_name caller prefix {prefix:?}"
        )));
    }
    Ok(())
}

fn validate_repo_block(repo: &RepoConfig) -> Result<(), ConfigError> {
    if repo.id == 0 || repo.owner_id == 0 {
        return Err(ConfigError::Validation(
            "repo.id and repo.owner_id must be non-zero".to_owned(),
        ));
    }
    if !is_valid_git_branch_name(&repo.default_branch) {
        return Err(ConfigError::Validation(format!(
            "invalid repo.default_branch {:?}",
            repo.default_branch
        )));
    }
    if !repo.oidc_issuer.starts_with("https://") {
        return Err(ConfigError::Validation(format!(
            "repo.oidc_issuer must start with https://, got {:?}",
            repo.oidc_issuer
        )));
    }
    let _ = repo.signer_policy()?;
    Ok(())
}

fn validate_tcb_block(repo: &RepoConfig, raw: RawTcbConfig) -> Result<TcbConfig, ConfigError> {
    let _ = repo;
    if raw.owner_user_ids.contains(&0) {
        return Err(ConfigError::Validation(
            "tcb.owner_user_ids must not contain 0".to_owned(),
        ));
    }
    if !is_workflow_dir_yaml(&raw.review_signal_workflow) {
        return Err(ConfigError::Validation(format!(
            "tcb.review_signal_workflow `{}` must be `.github/workflows/*.y[a]ml`",
            raw.review_signal_workflow
        )));
    }
    if !is_workflow_dir_yaml(&raw.review_rerun_workflow) {
        return Err(ConfigError::Validation(format!(
            "tcb.review_rerun_workflow `{}` must be `.github/workflows/*.y[a]ml`",
            raw.review_rerun_workflow
        )));
    }
    if raw.review_signal_workflow == raw.review_rerun_workflow {
        return Err(ConfigError::Validation(
            "tcb.review_signal_workflow and tcb.review_rerun_workflow must be distinct".to_owned(),
        ));
    }

    for wf_base in &raw.non_tcb_workflows {
        if wf_base.contains('/')
            || !(wf_base.ends_with(".yml") || wf_base.ends_with(".yaml"))
            || RepoRelPath::new(&format!(".github/workflows/{wf_base}")).is_err()
        {
            return Err(ConfigError::Validation(format!(
                "invalid tcb.non_tcb_workflows basename {wf_base:?}"
            )));
        }
        let full = RepoRelPath::new(&format!(".github/workflows/{wf_base}"))?;
        if full == raw.review_signal_workflow || full == raw.review_rerun_workflow {
            return Err(ConfigError::Validation(format!(
                "tcb.non_tcb_workflows `{wf_base}` collides with review workflow"
            )));
        }
    }

    for (i, p1) in raw.non_tcb_subtrees.iter().enumerate() {
        for p2 in &raw.non_tcb_subtrees[i + 1..] {
            if !p1.is_prefix_disjoint(p2) {
                return Err(ConfigError::Validation(format!(
                    "tcb.non_tcb_subtrees `{p1}` and `{p2}` overlap"
                )));
            }
        }
    }

    for g in &raw.extra_executable_paths {
        compile_selector_glob(g)?;
    }

    let caller: CallerMode = raw.caller.into();
    match &caller {
        CallerMode::RepoRuleset {
            caller_workflows,
            gate_check_name,
            ..
        } => {
            let prefix = gate_check_name.strip_suffix(" / gate").ok_or_else(|| {
                ConfigError::Validation(format!(
                    "RepoRuleset gate_check_name {gate_check_name:?} must match `<caller_prefix> / gate`"
                ))
            })?;
            validate_caller_prefix(prefix)?;
            let mut seen_cw = BTreeSet::new();
            for cw in caller_workflows {
                if !is_workflow_dir_yaml(cw) {
                    return Err(ConfigError::Validation(format!(
                        "caller_workflow `{cw}` must be `.github/workflows/*.y[a]ml`"
                    )));
                }
                if !seen_cw.insert(cw.clone()) {
                    return Err(ConfigError::Validation(format!(
                        "duplicate caller_workflow `{cw}`"
                    )));
                }
                if cw == &raw.review_signal_workflow || cw == &raw.review_rerun_workflow {
                    return Err(ConfigError::Validation(format!(
                        "caller_workflow `{cw}` collides with review workflow"
                    )));
                }
                if raw
                    .non_tcb_workflows
                    .iter()
                    .any(|b| cw.file_name() == b.as_str())
                {
                    return Err(ConfigError::Validation(format!(
                        "caller_workflow `{cw}` cannot appear in non_tcb_workflows"
                    )));
                }
            }
        }
        CallerMode::OrgRuleset {
            required_workflow_ids,
            push_caller_workflow,
            gate_check_name,
        } => {
            if !raw.non_tcb_workflows.is_empty() {
                return Err(ConfigError::Validation(
                    "tcb.non_tcb_workflows must be empty when caller.kind == \"org_ruleset\""
                        .to_owned(),
                ));
            }
            if required_workflow_ids.contains(&0) {
                return Err(ConfigError::Validation(
                    "required_workflow_ids must not contain 0".to_owned(),
                ));
            }
            if gate_check_name != "gate" {
                let prefix = gate_check_name.strip_suffix(" / gate").ok_or_else(|| {
                    ConfigError::Validation(format!(
                        "OrgRuleset gate_check_name {gate_check_name:?} must be `gate` or `<caller_prefix> / gate`"
                    ))
                })?;
                validate_caller_prefix(prefix)?;
            }
            if let Some(pw) = push_caller_workflow {
                if !is_workflow_dir_yaml(pw) {
                    return Err(ConfigError::Validation(format!(
                        "push_caller_workflow `{pw}` must be `.github/workflows/*.y[a]ml`"
                    )));
                }
                if pw == &raw.review_signal_workflow || pw == &raw.review_rerun_workflow {
                    return Err(ConfigError::Validation(format!(
                        "push_caller_workflow `{pw}` collides with review workflow"
                    )));
                }
            }
        }
    }

    Ok(TcbConfig {
        owner_user_ids: raw.owner_user_ids,
        allow_owner_self_approval: raw.allow_owner_self_approval,
        review_signal_workflow: raw.review_signal_workflow,
        review_rerun_workflow: raw.review_rerun_workflow,
        non_tcb_workflows: raw.non_tcb_workflows,
        non_tcb_subtrees: raw.non_tcb_subtrees,
        extra_executable_paths: raw.extra_executable_paths,
        caller,
    })
}

fn validate_env_key_not_reserved(key: &str, ctx: &str) -> Result<(), ConfigError> {
    if key.is_empty() || key.contains('=') || key.contains('\0') {
        return Err(ConfigError::Validation(format!(
            "invalid env/build_arg key {key:?} in {ctx}"
        )));
    }
    if RESERVED_ENV_EXACT.contains(&key) || RESERVED_ENV_PREFIXES.iter().any(|p| key.starts_with(p))
    {
        return Err(ConfigError::Validation(format!(
            "reserved environment variable `{key}` is forbidden in {ctx}"
        )));
    }
    Ok(())
}

fn interpolate_matrix_vars(
    template: &str,
    row: &BTreeMap<String, String>,
    check_id: &CheckId,
) -> Result<String, ConfigError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(idx) = rest.find("${") {
        out.push_str(&rest[..idx]);
        let after_open = &rest[idx + 2..];
        let Some(end_idx) = after_open.find('}') else {
            return Err(ConfigError::Validation(format!(
                "unclosed `${{...}}` interpolation in check `{check_id}`: {template:?}"
            )));
        };
        let expr = &after_open[..end_idx];
        let Some(mkey) = expr.strip_prefix("matrix.") else {
            return Err(ConfigError::Validation(format!(
                "unsupported interpolation `${{{expr}}}` in check `{check_id}` (only `${{matrix.<key>}}` is allowed)"
            )));
        };
        let val = row.get(mkey).ok_or_else(|| {
            ConfigError::Validation(format!(
                "unknown matrix key `{mkey}` in `${{matrix.{mkey}}}` for check `{check_id}`"
            ))
        })?;
        out.push_str(val);
        rest = &after_open[end_idx + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn sanitize_matrix_id_fragment(raw: &str) -> Result<String, ConfigError> {
    let mut s = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            s.push(ch.to_ascii_lowercase());
        } else if matches!(ch, '.' | '_' | '-' | '/' | ':' | ' ') {
            s.push('-');
        } else {
            return Err(ConfigError::Validation(format!(
                "matrix value {raw:?} contains unsupported character `{ch}` for CheckId expansion"
            )));
        }
    }
    let trimmed = s.trim_matches('-').to_owned();
    if trimmed.is_empty() {
        return Err(ConfigError::Validation(format!(
            "matrix value {raw:?} expands to an empty CheckId fragment"
        )));
    }
    Ok(trimmed)
}

fn expand_cartesian_matrix(
    matrix: &BTreeMap<String, NonEmptyVec<String>>,
    matrix_exclude: &[BTreeMap<String, String>],
    base_id: &CheckId,
) -> Result<Vec<BTreeMap<String, String>>, ConfigError> {
    if matrix.is_empty() {
        if !matrix_exclude.is_empty() {
            return Err(ConfigError::Validation(format!(
                "check `{base_id}` specifies `matrix_exclude` without `matrix`"
            )));
        }
        return Ok(vec![BTreeMap::new()]);
    }

    for (idx, filt) in matrix_exclude.iter().enumerate() {
        if filt.is_empty() {
            return Err(ConfigError::Validation(format!(
                "check `{base_id}` `matrix_exclude[{idx}]` must not be empty"
            )));
        }
        for fk in filt.keys() {
            if !matrix.contains_key(fk) {
                return Err(ConfigError::Validation(format!(
                    "check `{base_id}` `matrix_exclude[{idx}]` references unknown matrix key `{fk}`"
                )));
            }
        }
    }

    let mut rows: Vec<BTreeMap<String, String>> = vec![BTreeMap::new()];
    for (k, vals) in matrix {
        let mut next = Vec::with_capacity(rows.len() * vals.len());
        for r in &rows {
            for v in vals {
                let mut nr = r.clone();
                nr.insert(k.clone(), v.clone());
                next.push(nr);
            }
        }
        rows = next;
    }

    rows.retain(|row| {
        !matrix_exclude
            .iter()
            .any(|filt| filt.iter().all(|(fk, fv)| row.get(fk) == Some(fv)))
    });
    if rows.is_empty() {
        return Err(ConfigError::Validation(format!(
            "check `{base_id}` `matrix_exclude` pruned all matrix rows"
        )));
    }
    Ok(rows)
}

fn validate_selector_syntax(sel: &InputSelector) -> Result<(), ConfigError> {
    match sel {
        InputSelector::Glob { include, exclude } => {
            for g in include.iter().chain(exclude.iter()) {
                compile_selector_glob(g)?;
            }
        }
        InputSelector::CargoWorkspace {
            manifest_path,
            exclude,
        } => {
            if manifest_path.file_name() != "Cargo.toml" {
                return Err(ConfigError::Validation(format!(
                    "cargo_workspace manifest_path `{manifest_path}` must end with `Cargo.toml`"
                )));
            }
            for g in exclude {
                compile_selector_glob(g)?;
            }
        }
    }
    Ok(())
}

impl ChecksConfig {
    /// Parses and validates `checks.toml` schema invariants (`0` `SourceTree`
    /// reads; call `validate_against_tree` for tree-bound closure and Cargo
    /// checks).
    pub fn parse_toml(toml_str: &str, config_path: &RepoRelPath) -> Result<Self, ConfigError> {
        let raw: RawChecksToml =
            toml::from_str(toml_str).map_err(|e| ConfigError::Toml(e.to_string()))?;
        if raw.schema_version != 1 {
            return Err(ConfigError::UnsupportedSchemaVersion(raw.schema_version));
        }

        validate_repo_block(&raw.repo)?;
        let tcb = validate_tcb_block(&raw.repo, raw.tcb)?;
        if let Some(ref pat) = raw.commit_policy.forbid_message_regex {
            Regex::new(pat).map_err(|e| {
                ConfigError::Validation(format!(
                    "invalid commit_policy.forbid_message_regex {pat:?}: {e}"
                ))
            })?;
        }

        // Validate `[pins.*]` and global injectivity of `PIN_<NORM_PIN>__<NORM_KEY>`.
        let mut all_projected_pin_vars: BTreeMap<String, (PinId, PinKey)> = BTreeMap::new();
        let mut pin_paths = BTreeSet::new();
        for (pin_id, pspec) in &raw.pins {
            if pspec.max_bytes == 0 {
                return Err(ConfigError::Validation(format!(
                    "pin `{pin_id}` max_bytes must be > 0"
                )));
            }
            if pspec.keys.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "pin `{pin_id}` must declare at least one key"
                )));
            }
            if !pin_paths.insert(pspec.path.clone()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate pin path `{}`",
                    pspec.path
                )));
            }
            if pspec.path == *config_path || pspec.path.as_str().starts_with(".github/") {
                return Err(ConfigError::Validation(format!(
                    "pin `{pin_id}` path `{}` overlaps ExecutableTcb",
                    pspec.path
                )));
            }
            for (pkey, pat) in &pspec.keys {
                let anchored = format!(r"\A(?:{pat})\z");
                Regex::new(&anchored).map_err(|e| {
                    ConfigError::Validation(format!("invalid regex for pin `{pin_id}.{pkey}`: {e}"))
                })?;
                let env_name = pin_env_var_name(pin_id, pkey);
                if let Some((prev_p, prev_k)) =
                    all_projected_pin_vars.insert(env_name.clone(), (pin_id.clone(), pkey.clone()))
                {
                    return Err(ConfigError::Validation(format!(
                        "projected pin variable `{env_name}` collides between `{prev_p}.{prev_k}` and `{pin_id}.{pkey}`"
                    )));
                }
            }
        }

        // Validate `non_tcb_subtrees` static disjointness against `.github`,
        // `docs`, `config_path`, `[pins.*].path`, `[images.*].dockerfile`, and
        // `extra_executable_paths`.
        let github_dir = RepoRelPath::new(".github").expect("static");
        let docs_dir = RepoRelPath::new("docs").expect("static");
        let extra_exec_pats: Vec<crate::tree::SelectorGlob> = tcb
            .extra_executable_paths
            .iter()
            .map(|g| compile_selector_glob(g))
            .collect::<Result<_, _>>()?;

        for sub in &tcb.non_tcb_subtrees {
            if !sub.is_prefix_disjoint(&github_dir) {
                return Err(ConfigError::Validation(format!(
                    "non_tcb_subtree `{sub}` overlaps `.github`"
                )));
            }
            if !sub.is_prefix_disjoint(&docs_dir) {
                return Err(ConfigError::Validation(format!(
                    "non_tcb_subtree `{sub}` overlaps `docs`"
                )));
            }
            if !sub.is_prefix_disjoint(config_path) {
                return Err(ConfigError::Validation(format!(
                    "non_tcb_subtree `{sub}` overlaps config_path `{config_path}`"
                )));
            }
            for pspec in raw.pins.values() {
                if !sub.is_prefix_disjoint(&pspec.path) {
                    return Err(ConfigError::Validation(format!(
                        "non_tcb_subtree `{sub}` overlaps pin path `{}`",
                        pspec.path
                    )));
                }
            }
            for (g_raw, g_pat) in tcb.extra_executable_paths.iter().zip(&extra_exec_pats) {
                let g_clean = g_raw.trim_end_matches("/**").trim_end_matches("/*");
                if let Ok(gp) = RepoRelPath::new(g_clean)
                    && !sub.is_prefix_disjoint(&gp)
                {
                    return Err(ConfigError::Validation(format!(
                        "non_tcb_subtree `{sub}` overlaps extra_executable_paths `{g_raw}`"
                    )));
                }
                let probe = sub.join_segment("__probe__")?;
                if crate::tree::selector_glob_matches(g_pat, &probe) {
                    return Err(ConfigError::Validation(format!(
                        "non_tcb_subtree `{sub}` matches extra_executable_paths `{g_raw}`"
                    )));
                }
            }
        }
        // Also verify `[pins.*].path` does not match `extra_executable_paths`.
        for (pin_id, pspec) in &raw.pins {
            if extra_exec_pats
                .iter()
                .any(|pat| crate::tree::selector_glob_matches(pat, &pspec.path))
            {
                return Err(ConfigError::Validation(format!(
                    "pin `{pin_id}` path `{}` overlaps extra_executable_paths",
                    pspec.path
                )));
            }
        }

        // Validate `[images.*]`.
        for (img_id, ispec) in &raw.images {
            if ispec.runner.trim().is_empty() {
                return Err(ConfigError::Validation(format!(
                    "image `{img_id}` runner must not be empty"
                )));
            }
            if raw.pins.values().any(|p| p.path == ispec.dockerfile) {
                return Err(ConfigError::Validation(format!(
                    "image `{img_id}` dockerfile `{}` overlaps a pin path",
                    ispec.dockerfile
                )));
            }
            for sub in &tcb.non_tcb_subtrees {
                if !sub.is_prefix_disjoint(&ispec.dockerfile) {
                    return Err(ConfigError::Validation(format!(
                        "non_tcb_subtree `{sub}` overlaps image `{img_id}` dockerfile `{}`",
                        ispec.dockerfile
                    )));
                }
            }
            for sel in &ispec.context {
                validate_selector_syntax(sel)?;
                if let InputSelector::Glob { include, .. } = sel {
                    for g_raw in include {
                        let g_clean = g_raw.trim_end_matches("/**").trim_end_matches("/*");
                        if let Ok(gp) = RepoRelPath::new(g_clean) {
                            for sub in &tcb.non_tcb_subtrees {
                                if !sub.is_prefix_disjoint(&gp) {
                                    return Err(ConfigError::Validation(format!(
                                        "non_tcb_subtree `{sub}` overlaps image `{img_id}` context `{g_raw}`"
                                    )));
                                }
                            }
                        }
                    }
                }
            }
            let mut img_pin_vars = BTreeSet::new();
            let mut seen_pins = BTreeSet::new();
            for pid in &ispec.pins {
                if !seen_pins.insert(pid) {
                    return Err(ConfigError::Validation(format!(
                        "duplicate pin `{pid}` on image `{img_id}`"
                    )));
                }
                let pspec = raw.pins.get(pid).ok_or_else(|| {
                    ConfigError::Validation(format!(
                        "image `{img_id}` references undefined pin `{pid}`"
                    ))
                })?;
                for pkey in pspec.keys.keys() {
                    img_pin_vars.insert(pin_env_var_name(pid, pkey));
                }
            }
            for ba_key in ispec.build_args.keys() {
                validate_env_key_not_reserved(ba_key, &format!("image `{img_id}` build_args"))?;
                if img_pin_vars.contains(ba_key) || ba_key.starts_with("PIN_") {
                    return Err(ConfigError::Validation(format!(
                        "image `{img_id}` build_arg `{ba_key}` collides with PIN_* namespace"
                    )));
                }
            }
        }

        // Validate `[caches.*]`.
        let reserved_mounts: Vec<AbsUnixPath> = RESERVED_SANDBOX_MOUNTS
            .iter()
            .map(|m| AbsUnixPath::new(m).expect("static"))
            .collect();
        for (slot_id, cspec) in &raw.caches {
            if cspec.max_bytes == 0 {
                return Err(ConfigError::Validation(format!(
                    "cache `{slot_id}` max_bytes must be > 0"
                )));
            }
            if cspec.mount.as_str() == "/" {
                return Err(ConfigError::Validation(format!(
                    "cache `{slot_id}` cannot mount at `/`"
                )));
            }
            for rm in &reserved_mounts {
                if !cspec.mount.is_prefix_disjoint(rm) {
                    return Err(ConfigError::Validation(format!(
                        "cache `{slot_id}` mount `{}` overlaps reserved sandbox mountpoint `{rm}`",
                        cspec.mount
                    )));
                }
            }
            for sel in &cspec.inputs {
                validate_selector_syntax(sel)?;
            }
            if let Some(ref cl) = cspec.cargo_locked
                && cl.workspace.file_name() != "Cargo.toml"
            {
                return Err(ConfigError::Validation(format!(
                    "cache `{slot_id}` cargo_locked.workspace `{}` must end with Cargo.toml",
                    cl.workspace
                )));
            }
        }

        // Expand `[[checks]]` statically.
        let mut expanded_checks: BTreeMap<CheckId, CheckSpec> = BTreeMap::new();
        for raw_chk in &raw.checks {
            for sel in &raw_chk.inputs {
                validate_selector_syntax(sel)?;
            }
            for (i, wd1) in raw_chk.writable_dirs.iter().enumerate() {
                for wd2 in &raw_chk.writable_dirs[i + 1..] {
                    if !wd1.is_prefix_disjoint(wd2) {
                        return Err(ConfigError::Validation(format!(
                            "check `{}` writable_dirs `{wd1}` and `{wd2}` overlap",
                            raw_chk.id
                        )));
                    }
                }
            }

            let mut outputs_map = BTreeMap::new();
            for out_spec in &raw_chk.outputs {
                if out_spec.max_bytes == 0 {
                    return Err(ConfigError::Validation(format!(
                        "check `{}` output `{}` max_bytes must be > 0",
                        raw_chk.id, out_spec.name
                    )));
                }
                if outputs_map
                    .insert(out_spec.name.clone(), out_spec.clone())
                    .is_some()
                {
                    return Err(ConfigError::Validation(format!(
                        "duplicate output `{}` on check `{}`",
                        out_spec.name, raw_chk.id
                    )));
                }
            }

            let mut chk_pin_vars = BTreeSet::new();
            let mut seen_chk_pins = BTreeSet::new();
            for pid in &raw_chk.pins {
                if !seen_chk_pins.insert(pid) {
                    return Err(ConfigError::Validation(format!(
                        "duplicate pin `{pid}` on check `{}`",
                        raw_chk.id
                    )));
                }
                let pspec = raw.pins.get(pid).ok_or_else(|| {
                    ConfigError::Validation(format!(
                        "check `{}` references undefined pin `{pid}`",
                        raw_chk.id
                    ))
                })?;
                for pkey in pspec.keys.keys() {
                    chk_pin_vars.insert(pin_env_var_name(pid, pkey));
                }
            }

            let rows =
                expand_cartesian_matrix(&raw_chk.matrix, &raw_chk.matrix_exclude, &raw_chk.id)?;
            for row in rows {
                let expanded_id = if row.is_empty() {
                    raw_chk.id.clone()
                } else {
                    let mut id_str = raw_chk.id.as_str().to_owned();
                    for (mk, mv) in &row {
                        let frag = sanitize_matrix_id_fragment(mv)?;
                        id_str.push_str(&format!("--{mk}-{frag}"));
                    }
                    CheckId::new(&id_str)?
                };
                if expanded_checks.contains_key(&expanded_id) {
                    return Err(ConfigError::Validation(format!(
                        "duplicate expanded CheckId `{expanded_id}`"
                    )));
                }

                let img_str = interpolate_matrix_vars(&raw_chk.image, &row, &expanded_id)?;
                let image = ImageId::new(&img_str)?;
                if !raw.images.contains_key(&image) {
                    return Err(ConfigError::Validation(format!(
                        "check `{expanded_id}` references undefined image `{image}`"
                    )));
                }

                let runner = interpolate_matrix_vars(&raw_chk.runner, &row, &expanded_id)?;
                if runner.trim().is_empty() {
                    return Err(ConfigError::Validation(format!(
                        "check `{expanded_id}` runner must not be empty"
                    )));
                }

                let shard_group = match &raw_chk.shard_group {
                    Some(sg_raw) => {
                        let sg = interpolate_matrix_vars(sg_raw, &row, &expanded_id)?;
                        if sg.trim().is_empty() {
                            return Err(ConfigError::Validation(format!(
                                "check `{expanded_id}` shard_group must not be empty"
                            )));
                        }
                        Some(sg)
                    }
                    None => None,
                };

                let workdir = match &raw_chk.workdir {
                    Some(w_raw) => {
                        let w_interp = interpolate_matrix_vars(w_raw, &row, &expanded_id)?;
                        let wd = RepoRelPath::new(&w_interp)?;
                        for sub in &tcb.non_tcb_subtrees {
                            if sub.is_prefix_of(&wd) {
                                return Err(ConfigError::Validation(format!(
                                    "check `{expanded_id}` workdir `{wd}` lies inside non_tcb_subtree `{sub}`"
                                )));
                            }
                        }
                        Some(wd)
                    }
                    None => None,
                };

                let mut cmd_vec = Vec::with_capacity(raw_chk.command.len());
                for arg in &raw_chk.command {
                    cmd_vec.push(interpolate_matrix_vars(arg, &row, &expanded_id)?);
                }
                if cmd_vec[0].is_empty() {
                    return Err(ConfigError::Validation(format!(
                        "check `{expanded_id}` command[0] must not be empty"
                    )));
                }
                let command = NonEmptyVec::new(cmd_vec)?;

                let mut env = BTreeMap::new();
                for (ek, ev) in &raw_chk.env {
                    validate_env_key_not_reserved(ek, &format!("check `{expanded_id}` env"))?;
                    if chk_pin_vars.contains(ek) || ek.starts_with("PIN_") {
                        return Err(ConfigError::Validation(format!(
                            "check `{expanded_id}` env `{ek}` collides with PIN_* namespace"
                        )));
                    }
                    env.insert(ek.clone(), interpolate_matrix_vars(ev, &row, &expanded_id)?);
                }

                let mut caches = Vec::with_capacity(raw_chk.caches.len());
                let mut seen_slots = BTreeSet::new();
                let mut mounted_paths: Vec<(CacheSlotId, AbsUnixPath)> = Vec::new();
                for c_raw in &raw_chk.caches {
                    let c_str = interpolate_matrix_vars(c_raw, &row, &expanded_id)?;
                    let slot = CacheSlotId::new(&c_str)?;
                    if !seen_slots.insert(slot.clone()) {
                        return Err(ConfigError::Validation(format!(
                            "duplicate cache slot `{slot}` on check `{expanded_id}`"
                        )));
                    }
                    let cspec = raw.caches.get(&slot).ok_or_else(|| {
                        ConfigError::Validation(format!(
                            "check `{expanded_id}` references undefined cache slot `{slot}`"
                        ))
                    })?;
                    for (prev_slot, prev_mount) in &mounted_paths {
                        if !cspec.mount.is_prefix_disjoint(prev_mount) {
                            return Err(ConfigError::Validation(format!(
                                "check `{expanded_id}` mounts overlapping caches `{prev_slot}` (`{prev_mount}`) and `{slot}` (`{}`)",
                                cspec.mount
                            )));
                        }
                    }
                    mounted_paths.push((slot.clone(), cspec.mount.clone()));
                    caches.push(slot);
                }

                let mut writable_dirs = raw_chk.writable_dirs.clone();
                writable_dirs.sort();

                expanded_checks.insert(
                    expanded_id.clone(),
                    CheckSpec {
                        id: expanded_id,
                        image,
                        sandbox: raw_chk.sandbox,
                        writable_dirs,
                        runner,
                        shard_group,
                        workdir,
                        pins: raw_chk.pins.clone(),
                        inputs: raw_chk.inputs.clone(),
                        command,
                        env,
                        events: raw_chk.events.clone(),
                        caches,
                        outputs: outputs_map.clone(),
                        max_age_days: raw_chk.max_age_days,
                    },
                );
            }
        }

        Ok(Self {
            schema_version: raw.schema_version,
            repo: raw.repo,
            tcb,
            commit_policy: raw.commit_policy,
            pins: raw.pins,
            images: raw.images,
            caches: raw.caches,
            checks: expanded_checks,
        })
    }

    /// Evaluates `[commit_policy]` against `(commit_oid, commit_message)` pairs.
    pub fn validate_commit_messages(&self, commits: &[(GitOid, String)]) -> Result<(), String> {
        let Some(ref pat) = self.commit_policy.forbid_message_regex else {
            return Ok(());
        };
        let rx = Regex::new(pat).expect("forbid_message_regex validated at parse_toml");
        for (oid, msg) in commits {
            if rx.is_match(msg) {
                return Err(format!(
                    "commit `{oid}` message matched forbidden commit_policy.forbid_message_regex `{pat}`"
                ));
            }
        }
        Ok(())
    }

    /// Returns the `ControlPlanePolicy` (`signer` + `caller`) of this config.
    pub fn control_plane(&self) -> ControlPlanePolicy {
        ControlPlanePolicy {
            signer: self
                .repo
                .signer_policy()
                .expect("validated during parse_toml"),
            caller: self.tcb.caller.clone(),
        }
    }

    /// Returns the sorted set of required `CheckId`s active on `event`.
    pub fn required_checks(&self, event: TriggerEvent) -> BTreeSet<CheckId> {
        self.checks
            .iter()
            .filter(|(_, spec)| spec.events.contains(&event))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Looks up a matrix-expanded `CheckSpec`.
    pub fn check(&self, id: &CheckId) -> Option<&CheckSpec> {
        self.checks.get(id)
    }

    /// Evaluates and validates a single `[pins.<PinId>]` file in `tree`.
    pub fn evaluate_pin(
        &self,
        tree: &dyn SourceTree,
        pin_id: &PinId,
    ) -> Result<BTreeMap<PinKey, String>, ConfigError> {
        let spec = self
            .pins
            .get(pin_id)
            .ok_or_else(|| ConfigError::Validation(format!("unknown pin `{pin_id}`")))?;
        for anc in spec.path.proper_ancestors() {
            if tree.kind_of(&anc)? != Some(crate::tree::EntryKind::Dir) {
                return Err(ConfigError::InvalidPinFile {
                    pin: pin_id.clone(),
                    path: spec.path.clone(),
                    reason: format!("ancestor `{anc}` is not a real non-symlink directory"),
                });
            }
        }
        let Some(TreeEntry::Regular { executable }) = tree.entry(&spec.path)? else {
            return Err(ConfigError::InvalidPinFile {
                pin: pin_id.clone(),
                path: spec.path.clone(),
                reason: "must be a regular non-symlink file".to_owned(),
            });
        };
        if executable {
            return Err(ConfigError::InvalidPinFile {
                pin: pin_id.clone(),
                path: spec.path.clone(),
                reason: "must be mode 100644 (non-executable)".to_owned(),
            });
        }
        let bytes = tree.read_blob(&spec.path)?;
        if bytes.len() as u64 > spec.max_bytes {
            return Err(ConfigError::InvalidPinFile {
                pin: pin_id.clone(),
                path: spec.path.clone(),
                reason: format!("size {} exceeds max_bytes {}", bytes.len(), spec.max_bytes),
            });
        }
        let text = std::str::from_utf8(&bytes).map_err(|e| ConfigError::InvalidPinFile {
            pin: pin_id.clone(),
            path: spec.path.clone(),
            reason: format!("invalid UTF-8: {e}"),
        })?;
        let tbl: toml::Table = toml::from_str(text).map_err(|e| ConfigError::InvalidPinFile {
            pin: pin_id.clone(),
            path: spec.path.clone(),
            reason: format!("invalid TOML: {e}"),
        })?;

        if tbl.len() != spec.keys.len() {
            return Err(ConfigError::InvalidPinFile {
                pin: pin_id.clone(),
                path: spec.path.clone(),
                reason: "key set does not match declared pin keys".to_owned(),
            });
        }

        let mut out = BTreeMap::new();
        for (pkey, pat) in &spec.keys {
            let Some(val) = tbl.get(pkey.as_str()).and_then(toml::Value::as_str) else {
                return Err(ConfigError::InvalidPinFile {
                    pin: pin_id.clone(),
                    path: spec.path.clone(),
                    reason: format!("key `{pkey}` missing or not a string"),
                });
            };
            if val.bytes().any(|b| matches!(b, b'\0' | b'\r' | b'\n')) {
                return Err(ConfigError::InvalidPinFile {
                    pin: pin_id.clone(),
                    path: spec.path.clone(),
                    reason: format!("key `{pkey}` contains forbidden control characters"),
                });
            }
            let rx = Regex::new(&format!(r"\A(?:{pat})\z")).expect("validated at config parse");
            if !rx.is_match(val) {
                return Err(ConfigError::InvalidPinFile {
                    pin: pin_id.clone(),
                    path: spec.path.clone(),
                    reason: format!("key `{pkey}` value {val:?} did not match `{pat}`"),
                });
            }
            out.insert(pkey.clone(), val.to_owned());
        }
        Ok(out)
    }
}

/// Evaluates a slice of `InputSelector`s against `tree` (passing optional
/// `workdir` for `CargoStandardPaths` upward config/toolchain walks) and
/// returns `(closure_paths, discovered_cargo_workspaces)`.
pub fn expand_selectors_in_tree(
    tree: &dyn SourceTree,
    selectors: &[InputSelector],
    all_paths: &[RepoRelPath],
    check_workdir: Option<&RepoRelPath>,
) -> Result<(BTreeSet<RepoRelPath>, Vec<StaticWorkspaceDiscovery>), ConfigError> {
    let mut closure = BTreeSet::new();
    let mut discoveries = Vec::new();
    let extra_wd: Vec<Option<RepoRelPath>> = vec![check_workdir.cloned()];

    for sel in selectors {
        match sel {
            InputSelector::Glob { include, exclude } => {
                closure.extend(filter_paths_by_globs(all_paths, include, exclude)?);
            }
            InputSelector::CargoWorkspace {
                manifest_path,
                exclude,
            } => {
                let disc = discover_workspace(tree, manifest_path, &extra_wd)?;
                closure.extend(expand_cargo_standard_paths(
                    tree, &disc, all_paths, exclude,
                )?);
                discoveries.push(disc);
            }
        }
    }
    Ok((closure, discoveries))
}

/// Validated closures and static Cargo workspaces computed across **all**
/// `[images]`, `[caches]`, and matrix-expanded `[[checks]]` in `cfg` (prior to
/// `events` filtering).
#[derive(Debug, Clone)]
pub struct TreeValidatedConfig {
    /// Validated build-context closures per `ImageId` (including `dockerfile`).
    pub image_closures: BTreeMap<ImageId, ValidatedSourceClosure>,
    /// SHA-256 digests of each `[images.<ImageId>].dockerfile` regular file.
    pub dockerfile_digests: BTreeMap<ImageId, Sha256Digest>,
    /// Validated input closures per `CacheSlotId` (including `Cargo.lock` when
    /// `cargo_locked` is enabled).
    pub cache_closures: BTreeMap<CacheSlotId, ValidatedSourceClosure>,
    /// Validated source closures per matrix-expanded `CheckId`.
    pub check_closures: BTreeMap<CheckId, ValidatedSourceClosure>,
    /// Evaluated pin values per `PinId`.
    pub evaluated_pins: BTreeMap<PinId, BTreeMap<PinKey, String>>,
}

impl TreeValidatedConfig {
    /// Constructs an empty placeholder strictly for short-circuited
    /// `TcbPlan::Blocked` plan emission (`0` scheduled images or checks).
    pub fn empty() -> Self {
        Self {
            image_closures: BTreeMap::new(),
            dockerfile_digests: BTreeMap::new(),
            cache_closures: BTreeMap::new(),
            check_closures: BTreeMap::new(),
            evaluated_pins: BTreeMap::new(),
        }
    }

    /// Projects the canonical `ImageRecipePreimage` for `image_id` from `(cfg, self)`.
    pub fn image_recipe_preimage(
        &self,
        cfg: &ChecksConfig,
        image_id: &ImageId,
    ) -> Result<ImageRecipePreimage, String> {
        let ispec = cfg
            .images
            .get(image_id)
            .ok_or_else(|| format!("missing image `{image_id}`"))?;
        let ctx_closure = self
            .image_closures
            .get(image_id)
            .ok_or_else(|| format!("missing validated context closure for `{image_id}`"))?;
        let df_sha = self
            .dockerfile_digests
            .get(image_id)
            .ok_or_else(|| format!("missing dockerfile sha256 for `{image_id}`"))?;
        let mut pins_map = BTreeMap::new();
        for pid in &ispec.pins {
            let pvals = self
                .evaluated_pins
                .get(pid)
                .ok_or_else(|| format!("missing evaluated pin `{pid}`"))?;
            pins_map.insert(pid.clone(), pvals.clone());
        }
        Ok(ImageRecipePreimage::new(
            ispec.dockerfile.clone(),
            *df_sha,
            ctx_closure.merkle_digest(),
            ispec.build_args.clone(),
            pins_map,
            ispec.platform,
            cfg.repo.slug.source_repo_url(),
        ))
    }

    /// Projects the canonical `CacheKeyPreimage` for `(check_id, slot_id)` from `(cfg, self)`.
    pub fn cache_key_preimage(
        &self,
        cfg: &ChecksConfig,
        check_id: &CheckId,
        slot_id: &CacheSlotId,
    ) -> Result<CacheKeyPreimage, String> {
        let cspec = cfg
            .check(check_id)
            .ok_or_else(|| format!("missing check `{check_id}`"))?;
        let slot_spec = cfg
            .caches
            .get(slot_id)
            .ok_or_else(|| format!("missing cache slot `{slot_id}`"))?;
        let slot_closure = self
            .cache_closures
            .get(slot_id)
            .ok_or_else(|| format!("missing cache closure `{slot_id}`"))?;
        let mut sel_env = BTreeMap::new();
        for ek in &slot_spec.env_keys {
            if let Some(ev) = cspec.env.get(ek) {
                sel_env.insert(ek.clone(), ev.clone());
            }
        }
        Ok(CacheKeyPreimage {
            slot: slot_id.clone(),
            scope: slot_spec.scope,
            inputs_merkle: slot_closure.merkle_digest(),
            env: sel_env,
            cargo_locked: slot_spec
                .cargo_locked
                .as_ref()
                .map(CargoLockedConfig::to_digest_spec),
        })
    }

    /// Projects the canonical `ActionPreimage` for `check_id` from `(cfg, self)`.
    pub fn action_preimage(
        &self,
        cfg: &ChecksConfig,
        check_id: &CheckId,
    ) -> Result<ActionPreimage, String> {
        let cspec = cfg
            .check(check_id)
            .ok_or_else(|| format!("missing check `{check_id}`"))?;
        let ispec = cfg
            .images
            .get(&cspec.image)
            .ok_or_else(|| format!("missing image `{}`", cspec.image))?;
        let chk_closure = self
            .check_closures
            .get(check_id)
            .ok_or_else(|| format!("missing check closure `{check_id}`"))?;
        let mut chk_pins = BTreeMap::new();
        for pid in &cspec.pins {
            let pvals = self
                .evaluated_pins
                .get(pid)
                .ok_or_else(|| format!("missing evaluated pin `{pid}`"))?;
            chk_pins.insert(pid.clone(), pvals.clone());
        }
        let mut cache_mounts = Vec::with_capacity(cspec.caches.len());
        for slot in &cspec.caches {
            let slot_spec = cfg
                .caches
                .get(slot)
                .ok_or_else(|| format!("missing cache slot `{slot}`"))?;
            cache_mounts.push(CacheMountBinding {
                slot: slot.clone(),
                mount: slot_spec.mount.clone(),
            });
        }
        cache_mounts.sort();
        Ok(ActionPreimage {
            check_id: check_id.clone(),
            source_merkle: chk_closure.merkle_digest(),
            platform: ispec.platform,
            sandbox: cspec.sandbox,
            writable_dirs: cspec.writable_dirs.clone(),
            workdir: cspec.workdir.clone(),
            command: cspec.command.as_slice().to_vec(),
            env: cspec.env.clone(),
            pins: chk_pins,
            cache_mounts,
            declared_outputs: cspec.outputs.keys().cloned().collect(),
        })
    }
}

/// Validates `cfg` against `tree` across **all** `[pins]`, `[images]`,
/// `[caches]` (including dual static `cargo_locked` audits), and **all**
/// matrix-expanded `[[checks]]` (before `events` filtering), enforcing
/// `non_tcb_subtrees` upward-walk non-containment (`¬P.is_prefix_of(D)`).
pub fn validate_config_against_tree(
    cfg: &ChecksConfig,
    tree: &dyn SourceTree,
) -> Result<TreeValidatedConfig, ConfigError> {
    let cached_tree = crate::tree::CachingSourceTree::new(tree);
    let tree: &dyn SourceTree = &cached_tree;
    let all_paths = tree.all_paths()?;

    let mut evaluated_pins = BTreeMap::new();
    for pid in cfg.pins.keys() {
        evaluated_pins.insert(pid.clone(), cfg.evaluate_pin(tree, pid)?);
    }

    let mut all_crate_dirs: BTreeSet<Option<RepoRelPath>> = BTreeSet::new();

    let mut image_closures = BTreeMap::new();
    let mut dockerfile_digests = BTreeMap::new();
    for (img_id, ispec) in &cfg.images {
        if !matches!(
            tree.entry(&ispec.dockerfile)?,
            Some(TreeEntry::Regular { .. })
        ) {
            return Err(ConfigError::Validation(format!(
                "image `{img_id}` dockerfile `{}` must exist as a regular non-symlink file",
                ispec.dockerfile
            )));
        }
        let df_bytes = tree.read_blob(&ispec.dockerfile)?;
        dockerfile_digests.insert(img_id.clone(), Sha256Digest::hash_bytes(&df_bytes));
        let (mut ctx_paths, discs) =
            expand_selectors_in_tree(tree, &ispec.context, &all_paths, None)?;
        ctx_paths.insert(ispec.dockerfile.clone());
        for d in &discs {
            all_crate_dirs.extend(d.all_crate_dirs());
        }
        for p in &ctx_paths {
            for sub in &cfg.tcb.non_tcb_subtrees {
                if sub.is_prefix_of(p) {
                    return Err(ConfigError::Validation(format!(
                        "image `{img_id}` context file `{p}` lies inside non_tcb_subtree `{sub}`"
                    )));
                }
            }
        }
        let validated = validate_source_closure(tree, &ctx_paths, None, &[])?;
        image_closures.insert(img_id.clone(), validated);
    }

    let mut cache_closures = BTreeMap::new();
    for (slot_id, cspec) in &cfg.caches {
        let (mut in_paths, discs) =
            expand_selectors_in_tree(tree, &cspec.inputs, &all_paths, None)?;
        for d in &discs {
            all_crate_dirs.extend(d.all_crate_dirs());
        }
        if let Some(ref cl) = cspec.cargo_locked {
            let disc = discover_workspace(tree, &cl.workspace, &[])?;
            all_crate_dirs.extend(disc.all_crate_dirs());
            let fetch_plan = audit_cargo_locked(tree, &cl.workspace, &cl.allowed_registries)?;
            in_paths.insert(fetch_plan.lockfile.0);
        }
        let validated = validate_source_closure(tree, &in_paths, None, &[])?;
        cache_closures.insert(slot_id.clone(), validated);
    }

    // Matrix-expanded checks typically share identical `(inputs, workdir,
    // writable_dirs)` tuples; memoize validated closures across identical keys
    // so large vendor trees are expanded and validated once per unique tuple.
    type CheckClosureKey<'a> = (
        &'a [InputSelector],
        Option<&'a RepoRelPath>,
        &'a [RepoRelPath],
    );
    let mut memo_check_closures: BTreeMap<CheckClosureKey<'_>, ValidatedSourceClosure> =
        BTreeMap::new();
    let mut check_closures = BTreeMap::new();
    for (chk_id, cspec) in &cfg.checks {
        let key = (
            cspec.inputs.as_slice(),
            cspec.workdir.as_ref(),
            cspec.writable_dirs.as_slice(),
        );
        let validated = if let Some(cached) = memo_check_closures.get(&key) {
            cached.clone()
        } else {
            let (chk_paths, discs) =
                expand_selectors_in_tree(tree, &cspec.inputs, &all_paths, cspec.workdir.as_ref())?;
            for d in &discs {
                all_crate_dirs.extend(d.all_crate_dirs());
            }
            let v = validate_source_closure(
                tree,
                &chk_paths,
                cspec.workdir.as_ref(),
                &cspec.writable_dirs,
            )?;
            memo_check_closures.insert(key, v.clone());
            v
        };
        check_closures.insert(chk_id.clone(), validated);
    }

    // Enforce `∀ P ∈ tcb.non_tcb_subtrees, ∀ D ∈ workdirs ∪ cargo_crate_dirs: ¬P.is_prefix_of(D)`.
    // Note: `D == None` (repository root `""`) is never prefixed by any non-empty
    // `RepoRelPath`, while ancestor dirs such as `Some("zerocopy")` above
    // `P = "zerocopy/vendor"` satisfy `!"zerocopy/vendor".is_prefix_of("zerocopy")`.
    for sub in &cfg.tcb.non_tcb_subtrees {
        for crate_dir in all_crate_dirs.iter().flatten() {
            if sub.is_prefix_of(crate_dir) {
                return Err(ConfigError::Validation(format!(
                    "discovered Cargo crate directory `{crate_dir}` lies inside non_tcb_subtree `{sub}`"
                )));
            }
        }
    }

    Ok(TreeValidatedConfig {
        image_closures,
        dockerfile_digests,
        cache_closures,
        check_closures,
        evaluated_pins,
    })
}
