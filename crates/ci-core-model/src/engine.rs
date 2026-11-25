//! Pure planner (`build_plan`), `(runner, sandbox, image_id)` shard packer,
//! Attempt Resolution Rule, literal 7-clause offline `evaluate_gate`, and
//! `review-rerun` state machine (`decide_review_rerun` + `O7` poll classifier).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::attest::{AttestError, verify_offline};
use crate::config::{ChecksConfig, TreeValidatedConfig};
use crate::digest::{ActionPreimage, CacheKeyPreimage, ImageRecipePreimage};
use crate::store::{PrReview, Registry, StoreTier};
use crate::tcb::{
    TcbError, TcbPlan, caller_allowed_effective, is_owner_approved,
    resolve_effective_control_plane, verify_engine_workflows,
};
use crate::types::{
    AbsUnixPath, CacheSlotId, CallerMode, CheckId, Claim, GitOid, ImageId, LookupTag, NonEmptyVec,
    OutputDigest, OutputName, Platform, RunMode, SandboxMode, Sha256Digest, SignerPolicy,
    TriggerEvent, UnixSecs, WorkflowRunMeta, expected_run_mode, is_valid_git_branch_name,
};

/// Maximum GitHub Actions matrix fan-out per job (`256`).
pub const MAX_EXECUTE_SHARDS: usize = 256;

/// Maximum plan-to-gate lifetime (`6` hours).
pub const MAX_PLAN_LIFETIME_SECS: u64 = 21_600;

/// Threshold (`5h 50m`) below which `review-rerun` uses `/rerun-failed-jobs`
/// rather than a full `/rerun` on `DataPin` `gate`-only blocks.
pub const PARTIAL_RERUN_MAX_AGE_SECS: u64 = 21_000;

/// Upstream GitHub Actions job conclusion/result supplied to `evaluate_gate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamJobResult {
    /// Job succeeded (`result == "success"`).
    Success,
    /// Job failed (`result == "failure"`).
    Failure,
    /// Job was skipped (`result == "skipped"`).
    Skipped,
    /// Job was cancelled (`result == "cancelled"`).
    Cancelled,
}

/// Upstream job status tuple observed at `publish` or `gate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedJobResults {
    /// Result of `needs.plan`.
    pub plan: UpstreamJobResult,
    /// Result of `needs.build-images`.
    pub build_images: UpstreamJobResult,
    /// Result of `needs.execute`.
    pub execute: UpstreamJobResult,
    /// Result of `needs.publish` (`Skipped` on `PrePublish` stage).
    pub publish: UpstreamJobResult,
}

/// Gate evaluation stage (`PrePublish` inside `publish` vs. `FinalGate` inside
/// `gate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalStage {
    /// Pre-signature check inside `publish`.
    PrePublish,
    /// Final required status-check evaluation inside `gate`.
    FinalGate,
}

/// Resolution of a single `[images.<ImageId>]` entry inside `plan.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImagePlan {
    /// Verified warm GHCR hit (`Claim::Image` + `HEAD @sha256:<M>`).
    Reused {
        /// `ImageRecipeDigest`.
        recipe: Sha256Digest,
        /// Single-platform OCI image manifest digest `M`.
        manifest: Sha256Digest,
        /// Canonical `JCS(Claim::Image)` bytes.
        raw_claim_bytes: Vec<u8>,
        /// SHA-256 lookup key into `plan_bundles`.
        bundle_sha256: Sha256Digest,
    },
    /// Cold miss scheduled in `build-images`.
    PendingBuild {
        /// `ImageRecipeDigest`.
        recipe: Sha256Digest,
        /// Frozen recipe preimage.
        preimage: ImageRecipePreimage,
        /// Runner label.
        runner: String,
        /// Target container platform.
        platform: Platform,
    },
}

impl ImagePlan {
    /// Returns the `ImageRecipeDigest` regardless of reuse state.
    pub fn recipe(&self) -> &Sha256Digest {
        match self {
            Self::Reused { recipe, .. } | Self::PendingBuild { recipe, .. } => recipe,
        }
    }
}

/// Deduplicated image build unit scheduled in `build-images`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingImageBuild {
    /// `ImageRecipeDigest` (`img-{meta,blob}-a<A>-<recipe16>`).
    pub recipe: Sha256Digest,
    /// All `ImageId`s sharing this exact `ImageRecipeDigest`.
    pub image_ids: NonEmptyVec<ImageId>,
    /// Runner label.
    pub runner: String,
    /// Target container platform.
    pub platform: Platform,
    /// Frozen recipe preimage.
    pub preimage: ImageRecipePreimage,
}

/// Planned cache mount on a scheduled check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedCacheSlot {
    /// Cache slot identifier.
    pub slot: CacheSlotId,
    /// Storage routing tier (`PrivateCache` or `PublicCas`).
    pub tier: StoreTier,
    /// Sandbox mount path.
    pub mount: AbsUnixPath,
    /// Maximum `.tar.zst` byte size.
    pub max_bytes: u64,
    /// Frozen `CacheKeyPreimage` (`PerImage` finalized once `M` is known).
    pub preimage: CacheKeyPreimage,
    /// Lexicographically first `CheckId ∈ R_exec` sharing this cache key.
    pub cold_miss_owner: CheckId,
}

/// Warm check receipt reused without sandbox execution (`c ∈ R_reuse`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReusedCheckReceipt {
    /// Check identifier.
    pub check_id: CheckId,
    /// Expected `ActionDigest`.
    pub expected_action: Sha256Digest,
    /// Canonical `JCS(Claim::Check)` bytes.
    pub raw_claim_bytes: Vec<u8>,
    /// SHA-256 lookup key into `plan_bundles`.
    pub bundle_sha256: Sha256Digest,
}

/// Scheduled check requiring sandbox execution (`c ∈ R_exec`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledCheckPlan {
    /// Check identifier.
    pub check_id: CheckId,
    /// Referenced `[images.<ImageId>]`.
    pub image_id: ImageId,
    /// Runner label.
    pub runner: String,
    /// Hermetic sandbox mode.
    pub sandbox: SandboxMode,
    /// Optional shard co-location key within `(runner, sandbox, image_id)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard_group: Option<String>,
    /// Frozen `ActionPreimage` (finalized with `M` in `execute` and `gate`).
    pub action_preimage: ActionPreimage,
    /// Planned cache mounts keyed by `CacheSlotId`.
    pub caches: BTreeMap<CacheSlotId, PlannedCacheSlot>,
}

/// Packed shard entry for `execute` (`<= 256` total shards, partitioned by
/// `(runner, sandbox, image_id)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteShardSpec {
    /// Zero-based shard index (`shard-{meta,blob}-a<A>-<shard_index>`).
    pub shard_index: u32,
    /// Runner label.
    pub runner: String,
    /// Hermetic sandbox mode (`Container` or `NestedBwrap`).
    pub sandbox: SandboxMode,
    /// Shared `ImageId` for all checks in this shard.
    pub image_id: ImageId,
    /// `true` iff `images[image_id]` is `ImagePlan::PendingBuild`.
    pub image_pending: bool,
    /// `true` iff `sandbox == SandboxMode::NestedBwrap`.
    pub needs_bwrap: bool,
    /// Ordered checks assigned to this shard.
    pub checks: NonEmptyVec<CheckId>,
}

/// Serialized `plan.json` uploaded inside `plan-a<A>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPlan {
    /// `github.run_attempt` that produced this plan.
    pub plan_attempt: u32,
    /// Unix timestamp when `plan` ran.
    pub evaluated_at: UnixSecs,
    /// Effective `RunMode` (`Enforce`, `ForceExecuteAll`, or `ShadowPrPlanOnly`).
    pub mode: RunMode,
    /// Trigger event (`PullRequest`, `MergeGroup`, or `Push`).
    pub event: TriggerEvent,
    /// Observed `GITHUB_REF`.
    pub runtime_ref: String,
    /// Observed `GITHUB_BASE_REF` (`Some` on `PullRequest`, `None` otherwise).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr_base_ref: Option<String>,
    /// Observed commit OID (`GITHUB_SHA`).
    pub event_sha: GitOid,
    /// Second parent OID (`event_sha^2 == pr_head_sha`) on `PullRequest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second_parent: Option<GitOid>,
    /// `true` strictly on default-branch `MergeGroup` and `Push`.
    pub publish_eligible: bool,
    /// `publish_eligible && (!pending_images.is_empty() || !scheduled_checks.is_empty())`.
    pub needs_publish: bool,
    /// SHA-256 of raw `checks.toml` bytes at `base_sha` (`event_sha` on `Push`).
    pub base_cfg_sha256: Sha256Digest,
    /// SHA-256 of raw `checks.toml` bytes at `event_sha`.
    pub candidate_cfg_sha256: Sha256Digest,
    /// Recorded `(base_tree_oid, [tree(S_1), ..., tree(S_k)])` on `MergeGroup`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_group_chain_trees: Option<(GitOid, Vec<GitOid>)>,
    /// Consumer-TCB authorization decision.
    pub tcb: TcbPlan,
    /// Per-`ImageId` resolution (`Reused` or `PendingBuild`).
    pub images: BTreeMap<ImageId, ImagePlan>,
    /// Deduplicated `PendingBuild` image recipes (`<= 256`).
    pub pending_images: Vec<PendingImageBuild>,
    /// Warm reused check receipts (`R_reuse`).
    pub reused_checks: BTreeMap<CheckId, ReusedCheckReceipt>,
    /// Scheduled checks (`R_exec`).
    pub scheduled_checks: BTreeMap<CheckId, ScheduledCheckPlan>,
    /// Packed `execute` shards (`<= 256`).
    pub shards: Vec<ExecuteShardSpec>,
}

/// Metadata uploaded as `img-meta-a<A>-<recipe16>` (`<1 KB`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuiltImageMeta {
    /// SHA-256 of `plan.json` binding this build to `plan`.
    pub plan_sha256: Sha256Digest,
    /// `github.run_attempt` that built this image.
    pub attempt: u32,
    /// `ImageRecipeDigest`.
    pub recipe: Sha256Digest,
    /// Single-platform OCI image manifest digest `M`.
    pub manifest: Sha256Digest,
    /// Verified `manifest.config.digest` (`<loaded_image_id> = sha256:<hex>`).
    pub verified_config_digest: Sha256Digest,
}

/// Hydrated cache receipt recorded on a check outcome for offline re-verification
/// and transitive `provenance_signers` propagation in `evaluate_gate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HydratedCacheRecord {
    /// Mounted cache slot identifier.
    pub slot: CacheSlotId,
    /// Finalized `CacheKeyDigest`.
    pub cache_key: Sha256Digest,
    /// Canonical `JCS(Claim::Cache)` bytes.
    pub raw_claim_bytes: Vec<u8>,
    /// SHA-256 lookup key into `ShardMeta::bundles` / `all_bundles`.
    pub bundle_sha256: Sha256Digest,
}

/// Updated cache archive staged by `execute` on trusted refs (`hydrated_archive != Some(new_archive)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedCacheUpdate {
    /// Cache slot identifier.
    pub slot: CacheSlotId,
    /// Finalized `CacheKeyDigest`.
    pub cache_key: Sha256Digest,
    /// SHA-256 of the deterministic `.tar.zst` archive.
    pub archive_sha256: Sha256Digest,
    /// Exact byte length of the `.tar.zst` archive.
    pub size_bytes: u64,
}

/// Per-check execution result inside `ShardMeta`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckExecStatus {
    /// Check exited `0` and all declared outputs passed `O_NOFOLLOW` capture.
    Passed,
    /// Check exited non-zero or failed output capture.
    Failed,
}

/// Per-check outcome recorded inside `shard-meta-a<A>-<idx>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckExecutionOutcome {
    /// Check identifier.
    pub check_id: CheckId,
    /// Pass/fail status.
    pub status: CheckExecStatus,
    /// Finalized `ActionDigest`.
    pub action: Sha256Digest,
    /// Captured declared outputs keyed by `OutputName`.
    pub outputs: BTreeMap<OutputName, OutputDigest>,
    /// Verified caches hydrated prior to sandbox launch.
    pub hydrated_caches: Vec<HydratedCacheRecord>,
    /// Content-changed caches staged after passing on trusted refs.
    pub staged_caches: Vec<StagedCacheUpdate>,
}

/// Metadata uploaded as `shard-meta-a<A>-<idx>` (`<25 KB`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShardMeta {
    /// SHA-256 of `plan.json` binding this shard to `plan`.
    pub plan_sha256: Sha256Digest,
    /// `github.run_attempt` that ran this shard.
    pub attempt: u32,
    /// Zero-based shard index.
    pub shard_index: u32,
    /// Outcomes for every check assigned to this shard.
    pub outcomes: Vec<CheckExecutionOutcome>,
    /// Deduplicated `Bundle0_3` JSON bytes (`hex(sha256) -> raw_bundle_json`).
    pub bundles: BTreeMap<Sha256Digest, Vec<u8>>,
}

/// Proof-derived output of `evaluate_gate` on acceptance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatePass {
    /// Accepted `ShadowPrPlanOnly` run (`0` shards executed; all `R_reuse`
    /// verified offline).
    ShadowPlanVerified,
    /// Accepted `PrePublish` stage, carrying proof-derived transitive
    /// `provenance_signers` for every `c ∈ R_exec`.
    ReadyToPublish {
        /// Map `c ∈ R_exec -> transitive upstream engine signer SHAs`.
        check_provenance: BTreeMap<CheckId, BTreeSet<GitOid>>,
    },
    /// Accepted `FinalGate` status check.
    Enforced,
}

/// Rejection reasons from `build_plan`, `resolve_attempt_records`, or
/// `evaluate_gate`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GateError {
    /// Workflow or job was cancelled (`!workflow_cancelled` / `publish != Cancelled`).
    #[error("workflow or publish job was cancelled")]
    Cancelled,
    /// `TcbPlan::Blocked` unapproved TCB changes.
    #[error("PR touches consumer TCB without owner approval: {0:?}")]
    TcbBlocked(Vec<String>),
    /// Clause 1 plan/config/repo/branch/caller/pinning/window/publish guard failed.
    #[error("gate clause 1 (plan/control-plane/branch/window guard) failed: {0}")]
    Clause1(String),
    /// Clause 2 consumer-TCB or PR approval guard failed.
    #[error("gate clause 2 (TCB authorization) failed: {0}")]
    Clause2(String),
    /// Clause 3 upstream job result consistency failed.
    #[error("gate clause 3 (upstream job consistency) failed: {0}")]
    Clause3(String),
    /// Clause 4 image reuse or `PendingBuild` multiplicity failed.
    #[error("gate clause 4 (image resolution) failed: {0}")]
    Clause4(String),
    /// Clause 5 exact-once check partition or multiplicity failed.
    #[error("gate clause 5 (exact-once check partition) failed: {0}")]
    Clause5(String),
    /// Clause 6 fresh execution outcome or hydrated cache verification failed.
    #[error("gate clause 6 (fresh check/cache verification) failed: {0}")]
    Clause6(String),
    /// Clause 7 offline cryptographic reuse verification failed.
    #[error("gate clause 7 (offline check reuse) failed: {0}")]
    Clause7(String),
    /// Attempt resolution encountered duplicate `(attempt, id)` artifacts.
    #[error("duplicate attempt record for attempt {attempt} key {key}")]
    DuplicateAttemptRecord {
        /// Conflicting run attempt number.
        attempt: u32,
        /// Duplicate recipe or shard key.
        key: String,
    },
    /// Underlying TCB error.
    #[error(transparent)]
    Tcb(#[from] TcbError),
    /// Underlying attestation error.
    #[error(transparent)]
    Attest(#[from] AttestError),
}

/// Trait implemented by attempt-scoped metadata records (`BuiltImageMeta`,
/// `ShardMeta`) for the Attempt Resolution Rule (`§6.2`).
pub trait AttemptScopedRecord {
    /// Key type (`Sha256Digest` for images, `u32` for shards).
    type Key: Ord + Clone + std::fmt::Display;

    /// Key identifying the build recipe or shard index.
    fn record_key(&self) -> Self::Key;
    /// Bound `plan.json` SHA-256 digest.
    fn record_plan_sha256(&self) -> &Sha256Digest;
    /// Run attempt `A` that emitted this record.
    fn record_attempt(&self) -> u32;
}

impl AttemptScopedRecord for BuiltImageMeta {
    type Key = Sha256Digest;

    fn record_key(&self) -> Self::Key {
        self.recipe
    }

    fn record_plan_sha256(&self) -> &Sha256Digest {
        &self.plan_sha256
    }

    fn record_attempt(&self) -> u32 {
        self.attempt
    }
}

impl AttemptScopedRecord for ShardMeta {
    type Key = u32;

    fn record_key(&self) -> Self::Key {
        self.shard_index
    }

    fn record_plan_sha256(&self) -> &Sha256Digest {
        &self.plan_sha256
    }

    fn record_attempt(&self) -> u32 {
        self.attempt
    }
}

/// Applies the Attempt Resolution Rule (`§6.2`): discards records whose
/// `plan_sha256 != expected_plan_sha256`, `A < plan_attempt`, or
/// `A > current_run_attempt`, rejects duplicates with identical `(A, key)`, and
/// selects the record with maximum `A` per `key`.
pub fn resolve_attempt_records<R: AttemptScopedRecord + Clone>(
    records: &[R],
    expected_plan_sha256: &Sha256Digest,
    plan_attempt: u32,
    current_run_attempt: u32,
) -> Result<BTreeMap<R::Key, R>, GateError> {
    let mut by_key_and_attempt: BTreeMap<(R::Key, u32), R> = BTreeMap::new();
    for rec in records {
        if rec.record_plan_sha256() != expected_plan_sha256 {
            continue;
        }
        let a = rec.record_attempt();
        if a < plan_attempt || a > current_run_attempt {
            continue;
        }
        let k = rec.record_key();
        if by_key_and_attempt
            .insert((k.clone(), a), rec.clone())
            .is_some()
        {
            return Err(GateError::DuplicateAttemptRecord {
                attempt: a,
                key: k.to_string(),
            });
        }
    }

    let mut winners: BTreeMap<R::Key, R> = BTreeMap::new();
    for ((k, _a), rec) in by_key_and_attempt {
        // `BTreeMap` iterates `(k, a)` in ascending `a` order, so later entries
        // strictly have higher `a` and overwrite earlier attempts cleanly.
        winners.insert(k, rec);
    }
    Ok(winners)
}

/// Packs scheduled checks into `<= 256` shards partitioned strictly by
/// `(runner, sandbox, image_id)`, co-locating checks that share an explicit
/// `shard_group` within the same compatibility partition.
pub fn pack_execute_shards(
    scheduled: &BTreeMap<CheckId, ScheduledCheckPlan>,
    images: &BTreeMap<ImageId, ImagePlan>,
) -> Result<Vec<ExecuteShardSpec>, String> {
    if scheduled.is_empty() {
        return Ok(Vec::new());
    }
    type CompatKey = (String, SandboxMode, ImageId);
    // Within each `(runner, sandbox, image_id)` partition, group checks sharing
    // `Some(shard_group)` into a single logical unit while keeping `None` checks
    // as singleton units.
    let mut compat_units: BTreeMap<CompatKey, Vec<Vec<CheckId>>> = BTreeMap::new();
    let mut named_groups: BTreeMap<(CompatKey, String), Vec<CheckId>> = BTreeMap::new();
    let mut singletons: BTreeMap<CompatKey, Vec<CheckId>> = BTreeMap::new();

    for (chk_id, splan) in scheduled {
        let compat = (splan.runner.clone(), splan.sandbox, splan.image_id.clone());
        match &splan.shard_group {
            Some(g) => {
                named_groups
                    .entry((compat, g.clone()))
                    .or_default()
                    .push(chk_id.clone());
            }
            None => {
                singletons.entry(compat).or_default().push(chk_id.clone());
            }
        }
    }
    for ((compat, _g), chks) in named_groups {
        compat_units.entry(compat).or_default().push(chks);
    }
    for (compat, chks) in singletons {
        let entry = compat_units.entry(compat).or_default();
        for chk in chks {
            entry.push(vec![chk]);
        }
    }

    if compat_units.len() > MAX_EXECUTE_SHARDS {
        return Err(format!(
            "distinct (runner, sandbox, image_id) groups ({}) exceed GitHub Actions 256-shard limit",
            compat_units.len()
        ));
    }

    let total_units: usize = compat_units.values().map(Vec::len).sum();
    let mut shards = Vec::new();
    let mut next_idx = 0u32;

    if total_units <= MAX_EXECUTE_SHARDS {
        for ((runner, sandbox, image_id), units) in compat_units {
            let image_pending =
                matches!(images.get(&image_id), Some(ImagePlan::PendingBuild { .. }));
            for unit in units {
                shards.push(ExecuteShardSpec {
                    shard_index: next_idx,
                    runner: runner.clone(),
                    sandbox,
                    image_id: image_id.clone(),
                    image_pending,
                    needs_bwrap: sandbox == SandboxMode::NestedBwrap,
                    checks: NonEmptyVec::new(unit).expect("unit is non-empty"),
                });
                next_idx += 1;
            }
        }
    } else {
        let group_count = compat_units.len();
        let extra_budget = MAX_EXECUTE_SHARDS - group_count;
        let mut group_quotas: Vec<(CompatKey, Vec<Vec<CheckId>>, usize)> = compat_units
            .into_iter()
            .map(|(k, v)| {
                let add = ((v.len() - 1) * extra_budget) / total_units.max(1);
                let quota = (1 + add).min(v.len());
                (k, v, quota)
            })
            .collect();
        let used: usize = group_quotas.iter().map(|(_, _, q)| *q).sum();
        let mut rem = MAX_EXECUTE_SHARDS.saturating_sub(used);
        for (_, v, q) in &mut group_quotas {
            while rem > 0 && *q < v.len() {
                *q += 1;
                rem -= 1;
            }
        }
        for ((runner, sandbox, image_id), units, shard_cnt) in group_quotas {
            let image_pending =
                matches!(images.get(&image_id), Some(ImagePlan::PendingBuild { .. }));
            let n = units.len();
            let k = shard_cnt.max(1);
            let base_sz = n / k;
            let rem_items = n % k;
            let mut offset = 0usize;
            for i in 0..k {
                let sz = base_sz + usize::from(i < rem_items);
                let mut flat: Vec<CheckId> = units[offset..offset + sz]
                    .iter()
                    .flatten()
                    .cloned()
                    .collect();
                flat.sort();
                offset += sz;
                shards.push(ExecuteShardSpec {
                    shard_index: next_idx,
                    runner: runner.clone(),
                    sandbox,
                    image_id: image_id.clone(),
                    image_pending,
                    needs_bwrap: sandbox == SandboxMode::NestedBwrap,
                    checks: NonEmptyVec::new(flat).expect("sz >= 1"),
                });
                next_idx += 1;
            }
        }
    }
    Ok(shards)
}

/// Decides whether check `check_id` inside `shard_checks` should pack and stage
/// a non-empty `<cache_dir>` on a trusted ref (`§5.2` + Obligation `O4`):
/// - Warm hit (`hydrated_archive.is_some()`): any passing check may stage when
///   `new_archive != hydrated_archive`.
/// - Cold miss (`hydrated_archive.is_none()`): `c == cold_miss_owner` stages,
///   AND (`O4`) when `cold_miss_owner` is in a different shard (or ran earlier
///   in this shard and left `<cache_dir>` empty without staging), the first
///   passing check in this shard that populates `<cache_dir>` may also stage
///   (`publish` deduplicates deterministically by lexicographically first
///   `c_updater ∈ R_exec`).
pub fn should_attempt_cache_pack(
    publish_eligible: bool,
    check_id: &CheckId,
    cold_miss_owner: &CheckId,
    hydrated_archive: Option<&Sha256Digest>,
    already_staged_in_shard: bool,
    shard_checks: &[CheckId],
) -> bool {
    if !publish_eligible || already_staged_in_shard {
        return false;
    }
    if hydrated_archive.is_some() {
        return true;
    }
    if check_id == cold_miss_owner {
        return true;
    }
    // Obligation `O4`: allow non-`c_owner` check to stage a non-empty cold-miss
    // archive if `c_owner` is not in this shard OR already ran earlier in this
    // shard without staging anything (`!already_staged_in_shard`).
    match shard_checks.iter().position(|c| c == cold_miss_owner) {
        None => true,
        Some(owner_pos) => {
            let my_pos = shard_checks
                .iter()
                .position(|c| c == check_id)
                .unwrap_or(usize::MAX);
            my_pos > owner_pos
        }
    }
}

/// Builds a deterministic `ExecutionPlan` + deduplicated `plan_bundles` map
/// (`sha256 -> Bundle0_3 JSON bytes`) for `target_cfg` (`event_sha`).
#[allow(clippy::too_many_arguments)]
pub fn build_plan(
    plan_attempt: u32,
    evaluated_at: UnixSecs,
    event: TriggerEvent,
    shadow_mode: bool,
    force_execute_all: bool,
    runtime_ref: String,
    pr_base_ref: Option<String>,
    event_sha: GitOid,
    second_parent: Option<GitOid>,
    publish_eligible: bool,
    base_cfg_sha256: Sha256Digest,
    candidate_cfg_sha256: Sha256Digest,
    merge_group_chain_trees: Option<(GitOid, Vec<GitOid>)>,
    tcb: TcbPlan,
    eff_signer: &SignerPolicy,
    target_cfg: &ChecksConfig,
    validated_target: &TreeValidatedConfig,
    registry: &dyn Registry,
) -> Result<(ExecutionPlan, BTreeMap<Sha256Digest, Vec<u8>>), String> {
    let mode = expected_run_mode(event, shadow_mode, force_execute_all);
    let mut bundles: BTreeMap<Sha256Digest, Vec<u8>> = BTreeMap::new();

    if matches!(tcb, TcbPlan::Blocked { .. }) {
        return Ok((
            ExecutionPlan {
                plan_attempt,
                evaluated_at,
                mode,
                event,
                runtime_ref,
                pr_base_ref,
                event_sha,
                second_parent,
                publish_eligible: false,
                needs_publish: false,
                base_cfg_sha256,
                candidate_cfg_sha256,
                merge_group_chain_trees,
                tcb,
                images: BTreeMap::new(),
                pending_images: Vec::new(),
                reused_checks: BTreeMap::new(),
                scheduled_checks: BTreeMap::new(),
                shards: Vec::new(),
            },
            bundles,
        ));
    }

    let required_ids = target_cfg.required_checks(event);

    // 1. Resolve `[images.*]` referenced by `required_ids`.
    let needed_image_ids: BTreeSet<ImageId> = required_ids
        .iter()
        .filter_map(|cid| target_cfg.check(cid).map(|c| c.image.clone()))
        .collect();

    let mut images: BTreeMap<ImageId, ImagePlan> = BTreeMap::new();
    let mut pending_by_recipe: BTreeMap<
        Sha256Digest,
        (Vec<ImageId>, String, Platform, ImageRecipePreimage),
    > = BTreeMap::new();

    for img_id in needed_image_ids {
        let ispec = target_cfg
            .images
            .get(&img_id)
            .ok_or_else(|| format!("missing image `{img_id}`"))?;
        let preimage = validated_target.image_recipe_preimage(target_cfg, &img_id)?;
        let recipe = preimage.digest();
        let itag = LookupTag::image_claim(&recipe);

        let mut reused_plan: Option<ImagePlan> = None;
        if mode != RunMode::ForceExecuteAll
            && let Ok(Some(raw_art)) = registry.fetch_claim_artifact(StoreTier::PublicCas, &itag)
            && let Ok(vc) = verify_offline(
                &itag,
                &raw_art.claim_bytes,
                &raw_art.bundle_bytes,
                eff_signer,
                evaluated_at,
            )
            && let Claim::Image {
                recipe: cr,
                manifest,
            } = vc.claim()
            && cr == &recipe
            && registry
                .head_oci_manifest_by_digest(StoreTier::PublicCas, manifest)
                .unwrap_or(false)
        {
            let b_sha = Sha256Digest::hash_bytes(&raw_art.bundle_bytes);
            bundles.insert(b_sha, raw_art.bundle_bytes);
            reused_plan = Some(ImagePlan::Reused {
                recipe,
                manifest: *manifest,
                raw_claim_bytes: raw_art.claim_bytes,
                bundle_sha256: b_sha,
            });
        }

        if let Some(rp) = reused_plan {
            images.insert(img_id, rp);
        } else {
            pending_by_recipe
                .entry(recipe)
                .and_modify(|(ids, _, _, _)| ids.push(img_id.clone()))
                .or_insert_with(|| {
                    (
                        vec![img_id.clone()],
                        ispec.runner.clone(),
                        ispec.platform,
                        preimage.clone(),
                    )
                });
            images.insert(
                img_id,
                ImagePlan::PendingBuild {
                    recipe,
                    preimage,
                    runner: ispec.runner.clone(),
                    platform: ispec.platform,
                },
            );
        }
    }

    let pending_images: Vec<PendingImageBuild> = if mode == RunMode::ShadowPrPlanOnly {
        Vec::new()
    } else {
        pending_by_recipe
            .into_iter()
            .map(
                |(recipe, (ids, runner, platform, preimage))| PendingImageBuild {
                    recipe,
                    image_ids: NonEmptyVec::new(ids).expect("non-empty"),
                    runner,
                    platform,
                    preimage,
                },
            )
            .collect()
    };

    // 2. Partition `R = target_cfg.required_checks(event)` into `R_reuse` and `R_exec`.
    type ProvisionalCacheMap =
        BTreeMap<CacheSlotId, (StoreTier, AbsUnixPath, u64, CacheKeyPreimage)>;
    type ProvisionalCheckEntry = (
        ImageId,
        String,
        SandboxMode,
        Option<String>,
        ActionPreimage,
        ProvisionalCacheMap,
    );
    let mut reused_checks: BTreeMap<CheckId, ReusedCheckReceipt> = BTreeMap::new();
    let mut provisional_scheduled: BTreeMap<CheckId, ProvisionalCheckEntry> = BTreeMap::new();

    for cid in &required_ids {
        let cspec = target_cfg
            .check(cid)
            .ok_or_else(|| format!("missing check `{cid}`"))?;
        let action_preimage = validated_target.action_preimage(target_cfg, cid)?;
        let mut cache_preimages = BTreeMap::new();
        for slot in &cspec.caches {
            let slot_spec = target_cfg
                .caches
                .get(slot)
                .ok_or_else(|| format!("missing cache slot `{slot}`"))?;
            let cpre = validated_target.cache_key_preimage(target_cfg, cid, slot)?;
            cache_preimages.insert(
                slot.clone(),
                (
                    slot_spec.tier,
                    slot_spec.mount.clone(),
                    slot_spec.max_bytes,
                    cpre,
                ),
            );
        }

        let mut reused_receipt: Option<ReusedCheckReceipt> = None;
        if mode != RunMode::ForceExecuteAll
            && let Some(ImagePlan::Reused { manifest, .. }) = images.get(&cspec.image)
        {
            let expected_action = action_preimage.finalize(manifest);
            let atag = LookupTag::check_claim(&expected_action);
            if let Ok(Some(raw_art)) = registry.fetch_claim_artifact(StoreTier::PublicCas, &atag)
                && let Ok(vc) = verify_offline(
                    &atag,
                    &raw_art.claim_bytes,
                    &raw_art.bundle_bytes,
                    eff_signer,
                    evaluated_at,
                )
                && let Claim::Check {
                    action, outputs, ..
                } = vc.claim()
            {
                let outputs_match = action == &expected_action
                    && outputs.len() == cspec.outputs.len()
                    && cspec.outputs.iter().all(|(oname, ospec)| {
                        outputs
                            .get(oname)
                            .is_some_and(|od| od.size_bytes <= ospec.max_bytes)
                    });
                // Enforce 6h (`MAX_PLAN_LIFETIME_SECS`) TTL margin so a
                // receipt reused during `plan` cannot expire before `gate`.
                let ttl_ok = match cspec.max_age_days {
                    None => true,
                    Some(days) => {
                        evaluated_at
                            .saturating_add(MAX_PLAN_LIFETIME_SECS)
                            .saturating_sub(vc.signing_time())
                            <= u64::from(days.get()) * 86_400
                    }
                };
                if outputs_match && ttl_ok {
                    let b_sha = Sha256Digest::hash_bytes(&raw_art.bundle_bytes);
                    bundles.insert(b_sha, raw_art.bundle_bytes);
                    reused_receipt = Some(ReusedCheckReceipt {
                        check_id: cid.clone(),
                        expected_action,
                        raw_claim_bytes: raw_art.claim_bytes,
                        bundle_sha256: b_sha,
                    });
                }
            }
        }

        if let Some(rr) = reused_receipt {
            reused_checks.insert(cid.clone(), rr);
        } else {
            provisional_scheduled.insert(
                cid.clone(),
                (
                    cspec.image.clone(),
                    cspec.runner.clone(),
                    cspec.sandbox,
                    cspec.shard_group.clone(),
                    action_preimage,
                    cache_preimages,
                ),
            );
        }
    }

    // Designate lexicographically first `c_owner ∈ R_exec` per
    // `(CacheKeyPreimage, Option<ImageRecipeDigest>)`.
    let mut cold_owners: BTreeMap<(CacheKeyPreimage, Option<Sha256Digest>), CheckId> =
        BTreeMap::new();
    for (cid, (img_id, _, _, _, _, cpres)) in &provisional_scheduled {
        let img_recipe = images.get(img_id).map(|ip| *ip.recipe());
        for (_, _, _, cpre) in cpres.values() {
            let bind_recipe = match cpre.scope {
                crate::types::CacheScope::PerImage => img_recipe,
                crate::types::CacheScope::CrossImage => None,
            };
            cold_owners
                .entry((cpre.clone(), bind_recipe))
                .or_insert_with(|| cid.clone());
        }
    }

    let mut scheduled_checks: BTreeMap<CheckId, ScheduledCheckPlan> = BTreeMap::new();
    for (cid, (image_id, runner, sandbox, shard_group, action_preimage, cpres)) in
        provisional_scheduled
    {
        let img_recipe = images.get(&image_id).map(|ip| *ip.recipe());
        let mut caches = BTreeMap::new();
        for (slot, (tier, mount, max_bytes, preimage)) in cpres {
            let bind_recipe = match preimage.scope {
                crate::types::CacheScope::PerImage => img_recipe,
                crate::types::CacheScope::CrossImage => None,
            };
            let cold_miss_owner = cold_owners
                .get(&(preimage.clone(), bind_recipe))
                .cloned()
                .unwrap_or_else(|| cid.clone());
            caches.insert(
                slot.clone(),
                PlannedCacheSlot {
                    slot,
                    tier,
                    mount,
                    max_bytes,
                    preimage,
                    cold_miss_owner,
                },
            );
        }
        scheduled_checks.insert(
            cid.clone(),
            ScheduledCheckPlan {
                check_id: cid,
                image_id,
                runner,
                sandbox,
                shard_group,
                action_preimage,
                caches,
            },
        );
    }

    let shards = if mode == RunMode::ShadowPrPlanOnly {
        Vec::new()
    } else {
        pack_execute_shards(&scheduled_checks, &images)?
    };

    let eff_publish_eligible = publish_eligible && mode != RunMode::ShadowPrPlanOnly;
    let needs_publish =
        eff_publish_eligible && (!pending_images.is_empty() || !scheduled_checks.is_empty());

    Ok((
        ExecutionPlan {
            plan_attempt,
            evaluated_at,
            mode,
            event,
            runtime_ref,
            pr_base_ref,
            event_sha,
            second_parent,
            publish_eligible: eff_publish_eligible,
            needs_publish,
            base_cfg_sha256,
            candidate_cfg_sha256,
            merge_group_chain_trees,
            tcb,
            images,
            pending_images,
            reused_checks,
            scheduled_checks,
            shards,
        },
        bundles,
    ))
}

/// Computes the live `{m,i,a,k}sha256-*` retention tag set on `default_branch`
/// HEAD (`ci-core plan --gc-keep`).
pub fn compute_gc_keep_tags(plan: &ExecutionPlan) -> BTreeSet<LookupTag> {
    let mut keep = BTreeSet::new();
    for iplan in plan.images.values() {
        keep.insert(LookupTag::image_claim(iplan.recipe()));
        if let ImagePlan::Reused { manifest, .. } = iplan {
            keep.insert(LookupTag::image_manifest(manifest));
        }
    }
    for rr in plan.reused_checks.values() {
        keep.insert(LookupTag::check_claim(&rr.expected_action));
    }
    for splan in plan.scheduled_checks.values() {
        let resolved_m = match plan.images.get(&splan.image_id) {
            Some(ImagePlan::Reused { manifest, .. }) => Some(manifest),
            _ => None,
        };
        if let Some(m) = resolved_m {
            keep.insert(LookupTag::check_claim(&splan.action_preimage.finalize(m)));
        }
        for cslot in splan.caches.values() {
            if let Ok(ckey) = cslot.preimage.finalize(resolved_m) {
                keep.insert(LookupTag::cache_claim(&ckey));
            }
        }
    }
    keep
}

/// Names the checks that explain an unexpected `execute` result, for the
/// Clause 3 rejection message.
///
/// When a shard fails a check, `execute` is `Failure` and Clause 3 rejects the
/// run before Clause 6 looks at individual outcomes. Without this suffix the
/// gate would report only the job result and hide which checks failed. The
/// listed outcomes come from shard metadata and are used only to describe a
/// rejection, never to accept a run. A shard missing from the list of reported
/// shards most likely errored before it could write its metadata.
fn describe_execute_failures(
    plan: &ExecutionPlan,
    shard_outcomes: &BTreeMap<u32, ShardMeta>,
) -> String {
    let failed: Vec<&str> = shard_outcomes
        .values()
        .flat_map(|smeta| &smeta.outcomes)
        .filter(|out| out.status != CheckExecStatus::Passed)
        .map(|out| out.check_id.as_str())
        .collect();
    let missing: Vec<u32> = plan
        .shards
        .iter()
        .map(|sh| sh.shard_index)
        .filter(|idx| !shard_outcomes.contains_key(idx))
        .collect();
    let mut msg = String::new();
    if !failed.is_empty() {
        msg.push_str(&format!("; failed checks: {}", failed.join(", ")));
    }
    if !missing.is_empty() {
        msg.push_str(&format!("; shards without metadata: {missing:?}"));
    }
    msg
}

/// Literal 7-clause compile-time-offline `GateAccepts` evaluator (`§6.3`).
///
/// Accepts neither `Registry` nor `GitHubApi`, making network I/O inside gate
/// evaluation impossible by construction.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_gate(
    stage: EvalStage,
    workflow_cancelled: bool,
    eval_now: UnixSecs,
    runtime_repo_slug: &str,
    runtime_repo_id: u64,
    runtime_event: TriggerEvent,
    runtime_ref: &str,
    runtime_base_ref: Option<&str>,
    runtime_event_sha: GitOid,
    pr_head_sha: Option<GitOid>,
    pr_base_cfg_sha256: Option<Sha256Digest>,
    caller_shadow_mode: bool,
    live_shadow_pr_authorized: bool,
    caller_force_execute_all: bool,
    live_cfg: &ChecksConfig,
    target_cfg: &ChecksConfig,
    target_cfg_sha256: Sha256Digest,
    live_tree_ok: Result<(), TcbError>,
    target_tree_ok: Result<(), TcbError>,
    commit_policy_ok: Result<(), String>,
    live_codeowners_errors: &[String],
    target_codeowners_errors: &[String],
    landed_prefix_ok: bool,
    observed_run: &WorkflowRunMeta,
    jobs: ObservedJobResults,
    plan_bytes: &[u8],
    expected_plan_sha256: Sha256Digest,
    plan: &ExecutionPlan,
    approval_reviews_by_pr: &BTreeMap<u64, Vec<PrReview>>,
    built_images: &BTreeMap<Sha256Digest, BuiltImageMeta>,
    shard_outcomes: &BTreeMap<u32, ShardMeta>,
    plan_bundles: &BTreeMap<Sha256Digest, Vec<u8>>,
) -> Result<GatePass, GateError> {
    // -----------------------------------------------------------------------
    // Clause 1: Plan Integrity, Dual-Config Binding, Repo/Control-Plane/
    // CODEOWNERS Guard, Non-Cancellation, Target-Branch/Prefix Binding, Exact
    // `RunMode`, & Non-Fatal Publish Guard.
    // -----------------------------------------------------------------------
    if workflow_cancelled {
        return Err(GateError::Cancelled);
    }
    if jobs.plan != UpstreamJobResult::Success {
        return Err(GateError::Clause1(format!(
            "jobs.plan == {:?} (expected Success)",
            jobs.plan
        )));
    }
    if let TcbPlan::Blocked { ref paths } = plan.tcb {
        return Err(GateError::TcbBlocked(
            paths.iter().map(ToString::to_string).collect(),
        ));
    }
    if Sha256Digest::hash_bytes(plan_bytes) != expected_plan_sha256 {
        return Err(GateError::Clause1(
            "sha256(plan_bytes) != expected_plan_sha256".to_owned(),
        ));
    }
    let parsed_from_bytes: ExecutionPlan = serde_json::from_slice(plan_bytes)
        .map_err(|e| GateError::Clause1(format!("plan.json parse error: {e}")))?;
    if &parsed_from_bytes != plan {
        return Err(GateError::Clause1(
            "deserialized plan_bytes != supplied ExecutionPlan".to_owned(),
        ));
    }
    if target_cfg_sha256 != plan.candidate_cfg_sha256 {
        return Err(GateError::Clause1(
            "target_cfg_sha256 != plan.candidate_cfg_sha256".to_owned(),
        ));
    }
    if runtime_event == TriggerEvent::PullRequest
        && pr_base_cfg_sha256 != Some(plan.base_cfg_sha256)
    {
        return Err(GateError::Clause1(
            "pr_base_cfg_sha256 != Some(plan.base_cfg_sha256)".to_owned(),
        ));
    }
    if !target_cfg.repo.same_identity(&live_cfg.repo) {
        return Err(GateError::Clause1(
            "target_cfg [repo] identity diverged from live_cfg [repo]".to_owned(),
        ));
    }
    if !runtime_repo_slug.eq_ignore_ascii_case(live_cfg.repo.slug.canonical()) {
        return Err(GateError::Clause1(format!(
            "GITHUB_REPOSITORY {runtime_repo_slug:?} != {:?}",
            live_cfg.repo.slug.canonical()
        )));
    }
    if runtime_repo_id != live_cfg.repo.id {
        return Err(GateError::Clause1(format!(
            "GITHUB_REPOSITORY_ID {runtime_repo_id} != {}",
            live_cfg.repo.id
        )));
    }
    if plan.event != runtime_event
        || plan.runtime_ref != runtime_ref
        || plan.pr_base_ref.as_deref() != runtime_base_ref
        || plan.event_sha != runtime_event_sha
    {
        return Err(GateError::Clause1(
            "plan event/ref/base_ref/event_sha mismatch against runtime environment".to_owned(),
        ));
    }

    let eff_cp = resolve_effective_control_plane(live_cfg, &plan.tcb)?;
    live_tree_ok?;
    target_tree_ok?;
    if let Err(msg) = commit_policy_ok {
        return Err(GateError::Clause1(format!("commit_policy rejected: {msg}")));
    }
    if matches!(live_cfg.tcb.caller, CallerMode::RepoRuleset { .. })
        && !live_codeowners_errors.is_empty()
    {
        return Err(GateError::Clause1(format!(
            "live default_branch CODEOWNERS errors: {live_codeowners_errors:?}"
        )));
    }
    if matches!(target_cfg.tcb.caller, CallerMode::RepoRuleset { .. })
        && !target_codeowners_errors.is_empty()
    {
        return Err(GateError::Clause1(format!(
            "target event_sha CODEOWNERS errors: {target_codeowners_errors:?}"
        )));
    }
    if !caller_allowed_effective(&eff_cp.caller, &plan.tcb, runtime_event, observed_run) {
        return Err(GateError::Clause1(format!(
            "unauthorized caller workflow {:?} (id={}, org_required={})",
            observed_run.path, observed_run.workflow_id, observed_run.is_org_required_workflow
        )));
    }
    verify_engine_workflows(
        &observed_run.referenced_workflows,
        &eff_cp.signer,
        runtime_event,
    )?;

    let def_br = live_cfg.repo.default_branch.as_str();
    match runtime_event {
        TriggerEvent::PullRequest => {
            let valid_pr_base = runtime_base_ref.is_some_and(is_valid_git_branch_name);
            if !valid_pr_base || plan.publish_eligible {
                return Err(GateError::Clause1(
                    "PullRequest requires valid non-empty base_ref and !publish_eligible"
                        .to_owned(),
                ));
            }
        }
        TriggerEvent::MergeGroup => {
            let prefix = format!("refs/heads/gh-readonly-queue/{def_br}/");
            let suffix = runtime_ref.strip_prefix(&prefix).unwrap_or_default();
            if suffix.is_empty() || !plan.publish_eligible || !landed_prefix_ok {
                return Err(GateError::Clause1(
                    "MergeGroup failed queue ref prefix, publish_eligible, or landed_prefix_ok"
                        .to_owned(),
                ));
            }
        }
        TriggerEvent::Push => {
            let expected_ref = format!("refs/heads/{def_br}");
            if runtime_ref != expected_ref || !plan.publish_eligible {
                return Err(GateError::Clause1(format!(
                    "Push requires ref == {expected_ref:?} and publish_eligible"
                )));
            }
        }
    }

    if plan.evaluated_at > eval_now.saturating_add(300) {
        return Err(GateError::Clause1(
            "plan.evaluated_at is more than 300s in the future".to_owned(),
        ));
    }
    if eval_now.saturating_sub(plan.evaluated_at) > MAX_PLAN_LIFETIME_SECS {
        return Err(GateError::Clause1(
            "plan lifetime exceeded 21,600s (6 hours)".to_owned(),
        ));
    }

    let expected_mode =
        expected_run_mode(runtime_event, caller_shadow_mode, caller_force_execute_all);
    if plan.mode != expected_mode {
        return Err(GateError::Clause1(format!(
            "plan.mode {:?} != expected_run_mode {:?}",
            plan.mode, expected_mode
        )));
    }

    let needs_pub = plan.publish_eligible
        && (!plan.pending_images.is_empty() || !plan.scheduled_checks.is_empty());
    if plan.needs_publish != needs_pub {
        return Err(GateError::Clause1(
            "plan.needs_publish inconsistent with pending work".to_owned(),
        ));
    }
    match stage {
        EvalStage::PrePublish => {
            if !needs_pub {
                return Err(GateError::Clause1(
                    "PrePublish invoked when needs_publish == false".to_owned(),
                ));
            }
        }
        EvalStage::FinalGate => {
            if jobs.publish == UpstreamJobResult::Cancelled {
                return Err(GateError::Cancelled);
            }
            if !needs_pub && jobs.publish != UpstreamJobResult::Skipped {
                return Err(GateError::Clause1(format!(
                    "expected jobs.publish == Skipped when !needs_publish, got {:?}",
                    jobs.publish
                )));
            }
            if needs_pub
                && !matches!(
                    jobs.publish,
                    UpstreamJobResult::Success | UpstreamJobResult::Failure
                )
            {
                return Err(GateError::Clause1(format!(
                    "expected jobs.publish in {{Success, Failure}} when needs_publish, got {:?}",
                    jobs.publish
                )));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Clause 2: TCB Authorization (Enforced on Enforcing & Trusted Runs;
    // `ShadowPrPlanOnly` Bring-Up Runs Require Default-Branch Shadow Posture).
    // -----------------------------------------------------------------------
    if runtime_event == TriggerEvent::PullRequest {
        if plan.second_parent.is_none() || plan.second_parent != pr_head_sha {
            return Err(GateError::Clause2(
                "PullRequest plan.second_parent != Some(pr_head_sha)".to_owned(),
            ));
        }
        if plan.tcb == TcbPlan::NotRequired && plan.candidate_cfg_sha256 != plan.base_cfg_sha256 {
            return Err(GateError::Clause2(
                "PullRequest TcbPlan::NotRequired requires candidate_cfg_sha256 == base_cfg_sha256"
                    .to_owned(),
            ));
        }
    }
    let is_shadow = plan.mode == RunMode::ShadowPrPlanOnly;
    if is_shadow
        && !live_shadow_pr_authorized
        && matches!(plan.tcb, TcbPlan::RequiresOwnerApproval { .. })
    {
        for (pr_num, head_sha) in match &plan.tcb {
            TcbPlan::RequiresOwnerApproval { required_prs, .. } => required_prs,
            _ => unreachable!(),
        } {
            let reviews = approval_reviews_by_pr.get(pr_num).ok_or_else(|| {
                GateError::Clause2(format!("missing PR reviews for required PR #{pr_num}"))
            })?;
            if !is_owner_approved(
                reviews,
                &live_cfg.tcb.owner_user_ids,
                live_cfg.tcb.allow_owner_self_approval,
                head_sha,
            ) {
                return Err(GateError::Clause2(format!(
                    "PR #{pr_num} at `{head_sha}` cannot enable shadow_mode without live owner approval"
                )));
            }
        }
    }
    if !is_shadow
        && let TcbPlan::RequiresOwnerApproval {
            ref required_prs, ..
        } = plan.tcb
    {
        for (pr_num, head_sha) in required_prs {
            let reviews = approval_reviews_by_pr.get(pr_num).ok_or_else(|| {
                GateError::Clause2(format!("missing PR reviews for required PR #{pr_num}"))
            })?;
            if !is_owner_approved(
                reviews,
                &live_cfg.tcb.owner_user_ids,
                live_cfg.tcb.allow_owner_self_approval,
                head_sha,
            ) {
                return Err(GateError::Clause2(format!(
                    "PR #{pr_num} at `{head_sha}` lacks live owner approval"
                )));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Clause 3: Upstream Job Consistency.
    // -----------------------------------------------------------------------
    if is_shadow {
        if stage != EvalStage::FinalGate
            || plan.needs_publish
            || jobs.build_images != UpstreamJobResult::Skipped
            || jobs.execute != UpstreamJobResult::Skipped
        {
            return Err(GateError::Clause3(
                "ShadowPrPlanOnly requires FinalGate, !needs_publish, and Skipped build_images/execute"
                    .to_owned(),
            ));
        }
    } else {
        let expected_bi = if plan.pending_images.is_empty() {
            UpstreamJobResult::Skipped
        } else {
            UpstreamJobResult::Success
        };
        if jobs.build_images != expected_bi {
            return Err(GateError::Clause3(format!(
                "jobs.build_images {:?} != expected {:?}",
                jobs.build_images, expected_bi
            )));
        }
        let expected_ex = if plan.scheduled_checks.is_empty() {
            UpstreamJobResult::Skipped
        } else {
            UpstreamJobResult::Success
        };
        if jobs.execute != expected_ex {
            return Err(GateError::Clause3(format!(
                "jobs.execute {:?} != expected {:?}{}",
                jobs.execute,
                expected_ex,
                describe_execute_failures(plan, shard_outcomes)
            )));
        }
    }

    // -----------------------------------------------------------------------
    // Clause 4: Image Resolution (Offline `Claim::Image` + PendingBuild 1-to-1).
    // -----------------------------------------------------------------------
    let mut resolved_image_manifests: BTreeMap<ImageId, Sha256Digest> = BTreeMap::new();
    let mut reused_image_signer: BTreeMap<ImageId, GitOid> = BTreeMap::new();
    let mut expected_pending_recipes: BTreeSet<Sha256Digest> = BTreeSet::new();
    for pbi in &plan.pending_images {
        if !expected_pending_recipes.insert(pbi.recipe) {
            return Err(GateError::Clause4(format!(
                "duplicate recipe `{}` in plan.pending_images",
                pbi.recipe
            )));
        }
    }

    if !is_shadow {
        let actual_built_recipes: BTreeSet<Sha256Digest> = built_images.keys().copied().collect();
        if actual_built_recipes != expected_pending_recipes {
            return Err(GateError::Clause4(
                "built_images recipes do not match plan.pending_images with multiplicity 1"
                    .to_owned(),
            ));
        }
        for (rec, bmeta) in built_images {
            if &bmeta.recipe != rec || bmeta.plan_sha256 != expected_plan_sha256 {
                return Err(GateError::Clause4(
                    "built_images metadata recipe/plan_sha256 mismatch".to_owned(),
                ));
            }
        }
    }

    for (img_id, iplan) in &plan.images {
        match iplan {
            ImagePlan::Reused {
                recipe,
                manifest,
                raw_claim_bytes,
                bundle_sha256,
            } => {
                let bundle_bytes = plan_bundles.get(bundle_sha256).ok_or_else(|| {
                    GateError::Clause4(format!(
                        "missing bundle `{bundle_sha256}` for reused image `{img_id}`"
                    ))
                })?;
                let itag = LookupTag::image_claim(recipe);
                let vc_img = verify_offline(
                    &itag,
                    raw_claim_bytes,
                    bundle_bytes,
                    &eff_cp.signer,
                    plan.evaluated_at,
                )?;
                let Claim::Image {
                    recipe: cr,
                    manifest: cm,
                } = vc_img.claim()
                else {
                    return Err(GateError::Clause4(format!(
                        "reused image `{img_id}` claim is not Claim::Image"
                    )));
                };
                if cr != recipe || cm != manifest {
                    return Err(GateError::Clause4(format!(
                        "reused image `{img_id}` recipe/manifest mismatch"
                    )));
                }
                resolved_image_manifests.insert(img_id.clone(), *manifest);
                reused_image_signer.insert(img_id.clone(), vc_img.signer_sha());
            }
            ImagePlan::PendingBuild { recipe, .. } => {
                if !is_shadow {
                    let bmeta = built_images.get(recipe).ok_or_else(|| {
                        GateError::Clause4(format!(
                            "PendingBuild image `{img_id}` (`{recipe}`) missing from built_images"
                        ))
                    })?;
                    resolved_image_manifests.insert(img_id.clone(), bmeta.manifest);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Clause 5: Exact-Once Check Partition Against `target_cfg`.
    // -----------------------------------------------------------------------
    let r_required = target_cfg.required_checks(runtime_event);
    let r_reuse: BTreeSet<CheckId> = plan.reused_checks.keys().cloned().collect();
    let r_exec: BTreeSet<CheckId> = plan.scheduled_checks.keys().cloned().collect();

    if !r_reuse.is_disjoint(&r_exec) {
        return Err(GateError::Clause5(
            "R_reuse and R_exec are not disjoint".to_owned(),
        ));
    }
    let union_set: BTreeSet<CheckId> = r_reuse.union(&r_exec).cloned().collect();
    if union_set != r_required {
        return Err(GateError::Clause5(
            "R_reuse ∪ R_exec != target_cfg.required_checks(runtime_event)".to_owned(),
        ));
    }
    if plan.mode == RunMode::ForceExecuteAll && !r_reuse.is_empty() {
        return Err(GateError::Clause5(
            "ForceExecuteAll requires R_reuse == ∅".to_owned(),
        ));
    }

    let mut outcomes_by_check: BTreeMap<
        CheckId,
        (&CheckExecutionOutcome, &BTreeMap<Sha256Digest, Vec<u8>>),
    > = BTreeMap::new();
    if !is_shadow {
        let expected_shard_indices: BTreeSet<u32> =
            plan.shards.iter().map(|s| s.shard_index).collect();
        let actual_shard_indices: BTreeSet<u32> = shard_outcomes.keys().copied().collect();
        if actual_shard_indices != expected_shard_indices {
            return Err(GateError::Clause5(
                "resolved shard_outcomes indices do not match plan.shards".to_owned(),
            ));
        }
        for smeta in shard_outcomes.values() {
            if smeta.plan_sha256 != expected_plan_sha256 {
                return Err(GateError::Clause5(
                    "shard_outcomes plan_sha256 mismatch".to_owned(),
                ));
            }
            for out in &smeta.outcomes {
                if outcomes_by_check
                    .insert(out.check_id.clone(), (out, &smeta.bundles))
                    .is_some()
                {
                    return Err(GateError::Clause5(format!(
                        "duplicate check outcome for `{}` across shards",
                        out.check_id
                    )));
                }
            }
        }
        let outcome_ids: BTreeSet<CheckId> = outcomes_by_check.keys().cloned().collect();
        if outcome_ids != r_exec {
            return Err(GateError::Clause5(
                "multiset of check_ids across shard_outcomes != R_exec".to_owned(),
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Clause 6: Fresh Execution, Offline Hydrated `Claim::Cache` Verification &
    // Transitive Provenance Derivation.
    // -----------------------------------------------------------------------
    let mut check_provenance: BTreeMap<CheckId, BTreeSet<GitOid>> = BTreeMap::new();
    if !is_shadow {
        for cid in &r_exec {
            let spec = target_cfg.check(cid).ok_or_else(|| {
                GateError::Clause6(format!("missing CheckSpec `{cid}` in target_cfg"))
            })?;
            let splan = plan.scheduled_checks.get(cid).expect("cid in r_exec");
            if splan.image_id != spec.image {
                return Err(GateError::Clause6(format!(
                    "scheduled check `{cid}` image_id != target_cfg"
                )));
            }
            let resolved_m = resolved_image_manifests
                .get(&splan.image_id)
                .ok_or_else(|| {
                    GateError::Clause6(format!(
                        "missing resolved image manifest for `{}` on check `{cid}`",
                        splan.image_id
                    ))
                })?;
            let (outcome, shard_bundles) =
                outcomes_by_check.get(cid).expect("verified in Clause 5");
            if outcome.status != CheckExecStatus::Passed {
                return Err(GateError::Clause6(format!("check `{cid}` did not pass")));
            }
            let expected_action = splan.action_preimage.finalize(resolved_m);
            if outcome.action != expected_action {
                return Err(GateError::Clause6(format!(
                    "check `{cid}` action `{}` != finalized `{expected_action}`",
                    outcome.action
                )));
            }
            let actual_out_keys: BTreeSet<OutputName> = outcome.outputs.keys().cloned().collect();
            let expected_out_keys: BTreeSet<OutputName> = spec.outputs.keys().cloned().collect();
            if actual_out_keys != expected_out_keys {
                return Err(GateError::Clause6(format!(
                    "check `{cid}` output keys {actual_out_keys:?} != declared {expected_out_keys:?}"
                )));
            }
            for (oname, odig) in &outcome.outputs {
                let max_b = spec.outputs[oname].max_bytes;
                if odig.size_bytes > max_b {
                    return Err(GateError::Clause6(format!(
                        "check `{cid}` output `{oname}` size {} > max_bytes {max_b}",
                        odig.size_bytes
                    )));
                }
            }

            let mut prov_set: BTreeSet<GitOid> = BTreeSet::new();
            if let Some(&img_signer) = reused_image_signer.get(&splan.image_id) {
                prov_set.insert(img_signer);
            }

            let mut seen_hydrated_slots = BTreeSet::new();
            for hrec in &outcome.hydrated_caches {
                if !seen_hydrated_slots.insert(hrec.slot.clone()) {
                    return Err(GateError::Clause6(format!(
                        "duplicate hydrated cache slot `{}` on check `{cid}`",
                        hrec.slot
                    )));
                }
                if !spec.caches.contains(&hrec.slot) {
                    return Err(GateError::Clause6(format!(
                        "hydrated cache slot `{}` is not declared on check `{cid}`",
                        hrec.slot
                    )));
                }
                let planned_slot = splan.caches.get(&hrec.slot).ok_or_else(|| {
                    GateError::Clause6(format!(
                        "hydrated cache slot `{}` missing from plan[`{cid}`]",
                        hrec.slot
                    ))
                })?;
                let cfg_slot = target_cfg.caches.get(&hrec.slot).ok_or_else(|| {
                    GateError::Clause6(format!(
                        "hydrated cache slot `{}` missing from target_cfg",
                        hrec.slot
                    ))
                })?;
                if planned_slot.tier != cfg_slot.tier {
                    return Err(GateError::Clause6(format!(
                        "cache slot `{}` tier mismatch against target_cfg",
                        hrec.slot
                    )));
                }
                let expected_ckey = planned_slot
                    .preimage
                    .finalize(Some(resolved_m))
                    .map_err(GateError::Clause6)?;
                if hrec.cache_key != expected_ckey {
                    return Err(GateError::Clause6(format!(
                        "hydrated cache `{}` key `{}` != finalized `{expected_ckey}`",
                        hrec.slot, hrec.cache_key
                    )));
                }
                let cbundle = shard_bundles
                    .get(&hrec.bundle_sha256)
                    .or_else(|| plan_bundles.get(&hrec.bundle_sha256))
                    .ok_or_else(|| {
                        GateError::Clause6(format!(
                            "missing bundle `{}` for hydrated cache `{}` on `{cid}`",
                            hrec.bundle_sha256, hrec.slot
                        ))
                    })?;
                let ktag = LookupTag::cache_claim(&hrec.cache_key);
                let vc_cache = verify_offline(
                    &ktag,
                    &hrec.raw_claim_bytes,
                    cbundle,
                    &eff_cp.signer,
                    eval_now,
                )?;
                let Claim::Cache {
                    key,
                    slot: claim_slot,
                    size_bytes,
                    provenance_signers: upstream_prov,
                    ..
                } = vc_cache.claim()
                else {
                    return Err(GateError::Clause6(format!(
                        "hydrated cache `{}` claim is not Claim::Cache",
                        hrec.slot
                    )));
                };
                if key != &expected_ckey
                    || claim_slot != &hrec.slot
                    || *size_bytes > cfg_slot.max_bytes
                {
                    return Err(GateError::Clause6(format!(
                        "hydrated cache `{}` key/slot/size mismatch",
                        hrec.slot
                    )));
                }
                prov_set.insert(vc_cache.signer_sha());
                prov_set.extend(upstream_prov.iter().copied());
            }

            check_provenance.insert(cid.clone(), prov_set);
        }
    }

    // -----------------------------------------------------------------------
    // Clause 7: Offline Cryptographic Reuse (`∀ c ∈ R_reuse`, Enforced Across
    // ALL Modes Including `ShadowPrPlanOnly`).
    // -----------------------------------------------------------------------
    for (cid, rr) in &plan.reused_checks {
        let spec = target_cfg.check(cid).ok_or_else(|| {
            GateError::Clause7(format!("missing CheckSpec `{cid}` in target_cfg"))
        })?;
        let bundle_bytes = plan_bundles.get(&rr.bundle_sha256).ok_or_else(|| {
            GateError::Clause7(format!(
                "missing bundle `{}` for reused check `{cid}`",
                rr.bundle_sha256
            ))
        })?;
        let atag = LookupTag::check_claim(&rr.expected_action);
        let vc = verify_offline(
            &atag,
            &rr.raw_claim_bytes,
            bundle_bytes,
            &eff_cp.signer,
            plan.evaluated_at,
        )?;
        let Claim::Check {
            action, outputs, ..
        } = vc.claim()
        else {
            return Err(GateError::Clause7(format!(
                "reused check `{cid}` claim is not Claim::Check"
            )));
        };
        if action != &rr.expected_action {
            return Err(GateError::Clause7(format!(
                "reused check `{cid}` action digest mismatch"
            )));
        }
        let actual_out_keys: BTreeSet<OutputName> = outputs.keys().cloned().collect();
        let expected_out_keys: BTreeSet<OutputName> = spec.outputs.keys().cloned().collect();
        if actual_out_keys != expected_out_keys {
            return Err(GateError::Clause7(format!(
                "reused check `{cid}` outputs {actual_out_keys:?} != declared {expected_out_keys:?}"
            )));
        }
        for (oname, odig) in outputs {
            let max_b = spec.outputs[oname].max_bytes;
            if odig.size_bytes > max_b {
                return Err(GateError::Clause7(format!(
                    "reused check `{cid}` output `{oname}` size {} > max_bytes {max_b}",
                    odig.size_bytes
                )));
            }
        }
        if let Some(days) = spec.max_age_days {
            let max_age_secs = u64::from(days.get()) * 86_400;
            if eval_now.saturating_sub(vc.signing_time()) > max_age_secs {
                return Err(GateError::Clause7(format!(
                    "reused check `{cid}` exceeded max_age_days ({})",
                    days.get()
                )));
            }
        }
    }

    if is_shadow {
        Ok(GatePass::ShadowPlanVerified)
    } else if stage == EvalStage::PrePublish {
        Ok(GatePass::ReadyToPublish { check_provenance })
    } else {
        Ok(GatePass::Enforced)
    }
}

/// In-flight run status summary inspected by `review-rerun` (`§6.4` + `O7`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InflightRunSnapshot {
    /// Overall workflow run status (`"queued"`, `"in_progress"`, `"completed"`, etc.).
    pub run_status: String,
    /// Status of job `plan` (`None` if not yet materialized).
    pub plan_status: Option<String>,
    /// Status of job `build-images` (`None` if absent).
    pub build_images_status: Option<String>,
    /// Status of job `execute` (`None` if absent).
    pub execute_status: Option<String>,
}

/// Action selected by `classify_inflight_run_poll` when `R.status != "completed"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflightRunAction {
    /// Run is already `"completed"`; proceed directly to `decide_review_rerun`.
    Completed,
    /// Leave `R` untouched (`0` cancel calls): `plan` has not started yet, or
    /// `plan == "completed"` while `build_images`/`execute` is actively
    /// `"in_progress"`, so `plan` or `gate` will read post-review state live.
    LeaveUntouched,
    /// Poll (`<= 660s`) until either `build_images`/`execute` enters
    /// `"in_progress"` or `R.status == "completed"`.
    PollUntilSettled,
}

/// Classifies a non-completed PR workflow run for `review-rerun` (`§6.4` +
/// Obligation `O7`: narrows the post-`plan` leave-untouched disjunct strictly to
/// `build_images == "in_progress" || execute == "in_progress"`, so post-`plan`
/// `"queued"` jobs awaiting skip evaluation enter the poll loop).
pub fn classify_inflight_run_poll(snap: &InflightRunSnapshot) -> InflightRunAction {
    if snap.run_status == "completed" {
        return InflightRunAction::Completed;
    }
    let plan_st = snap.plan_status.as_deref().unwrap_or("queued");
    if !matches!(plan_st, "in_progress" | "completed") {
        return InflightRunAction::LeaveUntouched;
    }
    if plan_st == "completed"
        && (snap.build_images_status.as_deref() == Some("in_progress")
            || snap.execute_status.as_deref() == Some("in_progress"))
    {
        return InflightRunAction::LeaveUntouched;
    }
    InflightRunAction::PollUntilSettled
}

/// Completed job conclusions of a candidate PR run inspected by `decide_review_rerun`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompletedRunJobs {
    /// Conclusion of `plan`.
    pub plan: UpstreamJobResult,
    /// Conclusion of `build-images` (`Skipped` if absent).
    pub build_images: UpstreamJobResult,
    /// Conclusion of `execute` (`Skipped` if absent).
    pub execute: UpstreamJobResult,
    /// Conclusion of `gate`.
    pub gate: UpstreamJobResult,
}

/// Rerun action emitted by pure `decide_review_rerun` (`§6.4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewRerunDecision {
    /// Do nothing (`0` REST mutations).
    NoOp,
    /// Trigger `POST /repos/{owner}/{repo}/actions/runs/{id}/rerun`.
    RerunFull,
    /// Trigger `POST /repos/{owner}/{repo}/actions/runs/{id}/rerun-failed-jobs`.
    RerunFailedJobs,
}

/// Pure review-rerun decision function (`§6.4`) for a completed PR run `R`:
/// - `approved == false`: triggers `RerunFull` iff `jobs.gate == Success` AND
///   it is NOT proven `NotRequired` under `live_cfg` (`run_valid_under_live`,
///   `plan_opt` has `NotRequired` with `candidate_cfg_sha256 == base_cfg_sha256`,
///   and `merge_ref_touches_tcb_or_pin == Some(false)`).
/// - `approved == true` (assuming `run_matches_allowed_cp == true`):
///   * `jobs.plan == Failure || matches!(plan.tcb, Blocked)` -> `RerunFull`;
///   * `jobs.gate == Failure` with `build_images`/`execute ∈ {Success, Skipped}`:
///     - `Some(plan)` with `RequiresOwnerApproval`: `RerunFailedJobs` if
///       `now - plan.evaluated_at <= 21_000`, else `RerunFull`;
///     - `None` (expired `plan-a<A>`) with `merge_ref_touches_tcb_or_pin == Some(true)`
///       -> `RerunFull`;
///   * otherwise `NoOp`.
pub fn decide_review_rerun(
    approved: bool,
    run_valid_under_live_cp: bool,
    run_matches_allowed_cp: bool,
    jobs: CompletedRunJobs,
    plan_opt: Option<&ExecutionPlan>,
    merge_ref_touches_tcb_or_pin: Option<bool>,
    now: UnixSecs,
) -> ReviewRerunDecision {
    if !approved {
        if jobs.gate != UpstreamJobResult::Success {
            return ReviewRerunDecision::NoOp;
        }
        let proven_ordinary_not_required = run_valid_under_live_cp
            && plan_opt.is_some_and(|p| {
                p.tcb == TcbPlan::NotRequired && p.candidate_cfg_sha256 == p.base_cfg_sha256
            })
            && merge_ref_touches_tcb_or_pin == Some(false);
        if proven_ordinary_not_required {
            ReviewRerunDecision::NoOp
        } else {
            ReviewRerunDecision::RerunFull
        }
    } else {
        if !run_matches_allowed_cp {
            return ReviewRerunDecision::NoOp;
        }
        if jobs.plan == UpstreamJobResult::Failure
            || matches!(plan_opt.map(|p| &p.tcb), Some(TcbPlan::Blocked { .. }))
        {
            return ReviewRerunDecision::RerunFull;
        }
        let compute_clean = matches!(
            jobs.build_images,
            UpstreamJobResult::Success | UpstreamJobResult::Skipped
        ) && matches!(
            jobs.execute,
            UpstreamJobResult::Success | UpstreamJobResult::Skipped
        );
        if jobs.gate == UpstreamJobResult::Failure && compute_clean {
            match plan_opt {
                Some(plan) => {
                    if matches!(plan.tcb, TcbPlan::RequiresOwnerApproval { .. }) {
                        if now.saturating_sub(plan.evaluated_at) <= PARTIAL_RERUN_MAX_AGE_SECS {
                            return ReviewRerunDecision::RerunFailedJobs;
                        }
                        return ReviewRerunDecision::RerunFull;
                    }
                }
                None => {
                    if merge_ref_touches_tcb_or_pin == Some(true) {
                        return ReviewRerunDecision::RerunFull;
                    }
                }
            }
        }
        ReviewRerunDecision::NoOp
    }
}
