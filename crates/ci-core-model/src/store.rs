//! Narrow storage (`Registry`) and read-only GitHub API (`GitHubApi`) traits.
//!
//! Neither OCI wire media-type framing nor HTTP client state leaks into
//! `ci-core-model`. `evaluate_gate` accepts neither trait, making network I/O
//! inside gate evaluation a compile-time error.

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::{GitOid, LookupTag, Sha256Digest, UnixSecs, WorkflowRunMeta};

/// Logical storage tier routed by the `Registry` implementation.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum StoreTier {
    /// Publicly readable (or repo-scoped on private repos) CAS repository
    /// (`ghcr.io/<lower_slug>/ci-cas`).
    PublicCas,
    /// Repository-private cache repository (`ghcr.io/<lower_slug>/ci-cache`).
    #[default]
    PrivateCache,
}

/// Reference to an already-uploaded or inline Sigstore `Bundle0_3` JSON blob
/// (`Layer 0` of a Claim OCI Artifact).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRef {
    /// SHA-256 digest of `bytes`.
    pub digest: Sha256Digest,
    /// Raw UTF-8 JSON bytes of the `Bundle0_3`.
    pub bytes: Vec<u8>,
}

impl BlobRef {
    /// Hashes `bytes` and constructs a `BlobRef`.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let digest = Sha256Digest::hash_bytes(&bytes);
        Self { digest, bytes }
    }
}

/// Descriptor for a pre-uploaded payload blob (`Layers 1..k` of a Claim OCI
/// Artifact).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobDescriptor {
    /// Verified SHA-256 digest of the uploaded blob.
    pub digest: Sha256Digest,
    /// Verified byte length of the uploaded blob.
    pub size_bytes: u64,
    /// OCI layer media type (`application/octet-stream` or `.tar.zst`).
    pub media_type: String,
    /// Optional `org.opencontainers.image.title` annotation (used for
    /// `<OutputName>` on `Claim::Check`).
    pub title: Option<String>,
}

/// Raw unverified Claim OCI Artifact downloaded from a `LookupTag`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawClaimArtifact {
    /// Raw OCI `Config` JSON bytes (`JCS(Claim)`).
    pub claim_bytes: Vec<u8>,
    /// Raw `Layer 0` Sigstore `Bundle0_3` JSON bytes.
    pub bundle_bytes: Vec<u8>,
    /// Descriptors of `Layers 1..k` payload blobs recorded in the manifest.
    pub payload_layers: Vec<BlobDescriptor>,
}

/// Typed storage errors returned by `Registry` implementations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StoreError {
    /// Retryable HTTP `429`/`5xx` or transient transport failure.
    #[error("transient registry error: {0}")]
    Transient(String),
    /// Authentication or authorization failure (`401`/`403`) on a required
    /// write or explicit output fetch.
    #[error("registry unauthorized: {0}")]
    Unauthorized(String),
    /// Requested manifest or blob did not exist (`404`).
    #[error("registry object not found: {0}")]
    NotFound(String),
    /// Content SHA-256, byte length, or OCI layout invariant failed
    /// verification.
    #[error("integrity digest/layout mismatch: {0}")]
    DigestMismatch(String),
    /// Malformed OCI manifest/layout or local filesystem error.
    #[error("invalid artifact or I/O failure: {0}")]
    InvalidFormat(String),
}

/// Blob transfer counts reported by `Registry::push_untouched_oci_layout`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BlobUploadStats {
    /// Blobs whose bytes were transferred to the registry.
    pub uploaded: u32,
    /// Total size of the transferred blobs.
    pub uploaded_bytes: u64,
    /// Blobs the registry already held, so nothing was transferred.
    pub skipped: u32,
}

/// Narrow 9-method content-addressed and claim-artifact storage interface.
pub trait Registry: Send + Sync {
    /// Fetches a Claim OCI Artifact (`Config` + `Layer 0` bundle + layer
    /// descriptors) by 72-char `LookupTag`.
    ///
    /// Read-only `404` and discovery `401`/`403` degrade to `Ok(None)`.
    fn fetch_claim_artifact(
        &self,
        tier: StoreTier,
        tag: &LookupTag,
    ) -> Result<Option<RawClaimArtifact>, StoreError>;

    /// Checks whether an untouched single-platform OCI image manifest exists at
    /// `@sha256:<digest>` (`404`/`401`/`403` degrade to `Ok(false)`).
    fn head_oci_manifest_by_digest(
        &self,
        tier: StoreTier,
        digest: &Sha256Digest,
    ) -> Result<bool, StoreError>;

    /// Pulls an untouched OCI image strictly by `@sha256:<digest>` into
    /// `dest_layout_dir` and enforces `verify_oci_layout(dest_layout_dir, digest)`,
    /// returning the verified `manifest.config.digest`.
    fn fetch_oci_image_by_digest(
        &self,
        tier: StoreTier,
        digest: &Sha256Digest,
        dest_layout_dir: &Path,
    ) -> Result<Sha256Digest, StoreError>;

    /// Streams a blob by `@sha256:<digest>` into `dest`, enforcing `<= max_bytes`
    /// and exact `sha256(bytes) == digest` before returning its byte count.
    fn fetch_blob_verified(
        &self,
        tier: StoreTier,
        digest: &Sha256Digest,
        dest: &Path,
        max_bytes: u64,
    ) -> Result<u64, StoreError>;

    /// Verifies `verify_oci_layout(layout_dir, expected_manifest)` locally
    /// first, uploads missing config/layer blobs, and pushes the untouched
    /// manifest to `anchor_tag` (`msha256-<M>`).
    fn push_untouched_oci_layout(
        &self,
        tier: StoreTier,
        layout_dir: &Path,
        expected_manifest: &Sha256Digest,
        anchor_tag: &LookupTag,
    ) -> Result<BlobUploadStats, StoreError>;

    /// Verifies `sha256(path) == expected_digest && len(path) == expected_size`
    /// locally first, then uploads the content-addressed blob if absent.
    ///
    /// Returns `true` if bytes were transferred and `false` if the registry
    /// already held the blob.
    fn upload_verified_blob(
        &self,
        tier: StoreTier,
        path: &Path,
        expected_digest: &Sha256Digest,
        expected_size: u64,
    ) -> Result<bool, StoreError>;

    /// Reports whether the registry holds blob `digest` with length
    /// `expected_size`.
    ///
    /// This answers the same question that `upload_verified_blob` asks before
    /// transferring bytes, so a caller may skip producing a local copy of a
    /// blob for which this returns `true`. `404`/`401`/`403` degrade to
    /// `Ok(false)`, which only costs the caller a redundant upload.
    fn blob_exists(
        &self,
        tier: StoreTier,
        digest: &Sha256Digest,
        expected_size: u64,
    ) -> Result<bool, StoreError>;

    /// Reports whether `anchor_tag` resolves to manifest bytes hashing to
    /// `expected_manifest` and the registry holds that manifest's config and
    /// every layer blob at their declared sizes.
    ///
    /// When this returns `true`, `push_untouched_oci_layout` with the same
    /// arguments would upload nothing and rewrite the tag with identical
    /// bytes. Any doubt (`404`/`401`/`403`, a tag pointing at other bytes,
    /// an unparsable manifest, or a missing blob) degrades to `Ok(false)`.
    fn oci_image_anchored(
        &self,
        tier: StoreTier,
        anchor_tag: &LookupTag,
        expected_manifest: &Sha256Digest,
    ) -> Result<bool, StoreError>;

    /// Uploads `claim_bytes` (`Config`) and `bundle_blob` (`Layer 0`,
    /// deduplicated per `(tier, bundle_blob.digest)`), then commits the Claim
    /// OCI Artifact manifest at `tag`.
    fn put_claim_artifact(
        &self,
        tier: StoreTier,
        tag: &LookupTag,
        claim_bytes: &[u8],
        bundle_blob: &BlobRef,
        payload_blobs: &[BlobDescriptor],
    ) -> Result<(), StoreError>;
}

/// Raw GitHub pull-request review state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrReviewState {
    /// Formal approval (`APPROVED`).
    Approved,
    /// Formal veto (`CHANGES_REQUESTED`).
    ChangesRequested,
    /// Dismissed review (`DISMISSED`).
    Dismissed,
    /// Comment-only review (`COMMENTED`).
    Commented,
    /// Unsubmitted draft (`PENDING`), ignored.
    Pending,
}

/// Pull-request review record from `GET /repos/{owner}/{repo}/pulls/{n}/reviews`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrReview {
    /// Numeric GitHub review ID (`tie-breaker` when `submitted_at` ties).
    pub review_id: u64,
    /// Numeric GitHub user ID of the reviewer.
    pub user_id: u64,
    /// Review state.
    pub state: PrReviewState,
    /// Commit OID at which the review was submitted (`None` if deleted/absent).
    pub commit_id: Option<GitOid>,
    /// Raw review body text (inspected only for `/ci-core {approve,unapprove}`).
    pub body: String,
    /// Submission timestamp in Unix seconds.
    pub submitted_at: UnixSecs,
}

/// Merge method configured on a GitHub repository's Merge Queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MergeMethod {
    /// Two-parent merge commit (`MERGE`).
    Merge,
    /// Single-parent squashed tree commit (`SQUASH`).
    Squash,
    /// Linear fast-forward / cherry-picked commit sequence (`REBASE`).
    Rebase,
}

/// Queue state of an entry in GitHub GraphQL `mergeQueue.entries`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MergeQueueEntryState {
    /// Actively merging at the head of the queue (`LOCKED`).
    Locked,
    /// Waiting for CI checks (`AWAITING_CHECKS`).
    AwaitingChecks,
    /// Ready to merge (`MERGEABLE`).
    Mergeable,
    /// Queued behind earlier entries (`QUEUED`).
    Queued,
    /// Unmergeable (`UNMERGEABLE`).
    Unmergeable,
}

/// Single entry inside a `MergeQueueSnapshot`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeQueueEntry {
    /// Pull request number.
    pub pr_number: u64,
    /// PR head commit OID (`pullRequest.headRefOid`), not the merge-group
    /// commit that GitHub reports as the entry's `headCommit`.
    pub head_oid: GitOid,
    /// PR base commit OID (`baseCommit.oid`, if reported).
    pub base_oid: Option<GitOid>,
    /// Queue entry state (`LOCKED`, `AWAITING_CHECKS`, etc.).
    pub state: MergeQueueEntryState,
}

/// Complete paginated snapshot of a branch's GitHub Merge Queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeQueueSnapshot {
    /// Configured `mergeMethod` (`MERGE`, `SQUASH`, or `REBASE`).
    pub merge_method: MergeMethod,
    /// Ordered queue entries from position 0 upward.
    pub entries: Vec<MergeQueueEntry>,
}

/// Metadata for an Actions run artifact (`GET .../actions/runs/{id}/artifacts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunArtifactMeta {
    /// Numeric artifact ID.
    pub id: u64,
    /// Artifact name (`plan-a1`, `img-meta-a1-...`, etc.).
    pub name: String,
    /// Size in bytes.
    pub size_in_bytes: u64,
    /// Whether the artifact has expired.
    pub expired: bool,
}

/// Error returned by `GitHubApi` read-only queries.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GhApiError {
    /// HTTP `404` resource not found.
    #[error("GitHub API 404 not found: {0}")]
    NotFound(String),
    /// HTTP or GraphQL failure.
    #[error("GitHub API error: {0}")]
    Request(String),
}

/// Strictly read-only GitHub REST/GraphQL interface used inside `ci.yml`
/// (`0 actions: write`).
pub trait GitHubApi: Send + Sync {
    /// Paginates all reviews on `pr_number` (`per_page=100`).
    fn list_pr_reviews_all(&self, pr_number: u64) -> Result<Vec<PrReview>, GhApiError>;

    /// Queries `mergeQueue` (`mergeMethod` + all paginated `entries`) on `branch`.
    fn get_merge_queue(&self, branch: &str) -> Result<MergeQueueSnapshot, GhApiError>;

    /// Queries `GET /repos/{owner}/{repo}/actions/runs/{run_id}`.
    fn get_run_metadata(&self, run_id: u64) -> Result<WorkflowRunMeta, GhApiError>;

    /// Queries `GET /repos/{owner}/{repo}/codeowners/errors?ref={git_sha}`
    /// (`404` -> `Err(GhApiError::NotFound)`).
    fn get_codeowners_errors(&self, git_sha: &GitOid) -> Result<Vec<String>, GhApiError>;

    /// Paginates non-expired run artifacts (`per_page=100`).
    fn list_run_artifacts(
        &self,
        run_id: u64,
        name_filter: Option<&str>,
    ) -> Result<Vec<RunArtifactMeta>, GhApiError>;

    /// Downloads an artifact `.zip` archive to `dest` (stripping `Authorization`
    /// on `302` redirect).
    fn download_artifact_zip(&self, artifact_id: u64, dest: &Path) -> Result<(), GhApiError>;
}
