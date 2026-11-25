//! Registry side of `ci-core publish`: pushes verified images and shard
//! blobs, then signs and commits their claims in two bottom-up batches.
//!
//! `cmd_publish` re-evaluates the gate first; everything here assumes the
//! gate accepted `built_images` and `shard_outcomes`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Instant;

use ci_core_cli::signer::{StagedClaim, commit_claims_bottom_up};
use ci_core_model::engine::{BuiltImageMeta, CheckExecStatus, ShardMeta};
use ci_core_model::store::{
    BlobDescriptor, BlobRef, GitHubApi, Registry, RunArtifactMeta, StoreTier,
};
use ci_core_model::types::{CacheSlotId, CheckId, Claim, GitOid, LookupTag, Sha256Digest};

use crate::{extract_zip_archive, unpack_tar_zst_dir};

/// Number of shard artifacts processed at once.
pub(crate) const SHARD_PARALLELISM: usize = 4;

/// Upper bound on the estimated disk use of shard artifacts being processed
/// at once (downloaded zip plus extracted blobs).
///
/// One image artifact on its own needs more than this (zip, `tar.zst`, and
/// unpacked layout), so the shard phase never raises the run's peak disk use
/// above the image phase's. A shard whose estimate exceeds the budget runs
/// alone.
const SHARD_DISK_BUDGET_BYTES: u64 = 4 << 30;

/// Gate-verified records that `publish` turns into registry content and claims.
pub(crate) struct PublishInputs<'a> {
    /// Images built in this run, keyed by recipe digest.
    pub built_images: &'a BTreeMap<Sha256Digest, BuiltImageMeta>,
    /// Shard results of this run, keyed by shard index.
    pub shard_outcomes: &'a BTreeMap<u32, ShardMeta>,
    /// Transitive provenance signers per executed check.
    pub check_provenance: &'a BTreeMap<CheckId, BTreeSet<GitOid>>,
    /// Storage tier of every configured cache slot.
    pub cache_tiers: &'a BTreeMap<CacheSlotId, StoreTier>,
    /// Artifacts uploaded by this workflow run.
    pub artifacts: &'a [RunArtifactMeta],
}

/// Counts of committed claims.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublishSummary {
    pub images: usize,
    pub caches: usize,
    pub checks: usize,
}

/// Signs one batch of staged claims, returning the `Bundle0_3` blob.
pub(crate) type BatchSigner<'a> = dyn FnMut(&[StagedClaim]) -> Result<BlobRef, String> + 'a;

/// Pushes images and shard blobs and commits their claims.
///
/// Image claims are signed and committed as soon as every image is in the
/// registry, before any shard artifact is touched. Cache and check claims
/// follow in a second batch. A run that times out or fails during the shard
/// phase therefore still records its images, and the next plan reuses them
/// instead of rebuilding.
///
/// Splitting the batch keeps the bottom-up order of
/// `commit_claims_bottom_up`: the first batch commits only `isha256-` tags,
/// and the second starts only after the first has fully committed, so every
/// `isha256-` tag still precedes every `ksha256-` tag, which precedes every
/// `asha256-` tag. Each claim is verified on its own against the bundle in
/// its `Layer 0` (`verify_offline` looks for the claim among the bundle's
/// subjects), so a claim's validity does not depend on which batch signed it.
///
/// Before a claim is signed, every blob it names is in the registry: either
/// this function uploaded it after verifying its local digest and size, or
/// the registry already held content with that digest and size. See
/// `publish_image` and `publish_shard_blobs` for why the second case is as
/// good as the first.
pub(crate) fn publish_verified_outcomes(
    inputs: &PublishInputs<'_>,
    api: &dyn GitHubApi,
    reg: &dyn Registry,
    sign_batch: &mut BatchSigner<'_>,
    work_dir: &Path,
    shard_parallelism: usize,
) -> Result<PublishSummary, String> {
    let start = Instant::now();

    // `publish` also runs when `execute` failed, so the gate can report the
    // failed checks. `evaluate_gate` already rejects that case (Clause 3
    // requires `execute == Success`, Clause 6 requires every outcome to be
    // `Passed`), but the code below stages a `Claim::Check` for every outcome
    // without looking at its status. Check again here, before any upload, so
    // a failed check can never be signed as a reusable receipt, even if the
    // gate changes.
    if let Some(out) = inputs
        .shard_outcomes
        .values()
        .flat_map(|smeta| &smeta.outcomes)
        .find(|out| out.status != CheckExecStatus::Passed)
    {
        return Err(format!(
            "refusing to publish: check `{}` did not pass",
            out.check_id
        ));
    }
    eprintln!(
        "publish: {} image(s) and {} shard(s) to publish, up to {} shard(s) at once",
        inputs.built_images.len(),
        inputs.shard_outcomes.len(),
        shard_parallelism.max(1),
    );

    let mut image_claims = Vec::with_capacity(inputs.built_images.len());
    for (recipe, bmeta) in inputs.built_images {
        publish_image(recipe, bmeta, inputs.artifacts, api, reg, work_dir, start)?;
        let iclaim = Claim::Image {
            recipe: *recipe,
            manifest: bmeta.manifest,
        };
        image_claims.push(
            StagedClaim::new(StoreTier::PublicCas, &iclaim, Vec::new())
                .map_err(|e| e.to_string())?,
        );
    }
    if !image_claims.is_empty() {
        sign_and_commit(reg, sign_batch, "image", &image_claims, &[], &[], start)?;
    }

    let winners = winning_cache_updaters(inputs)?;
    let mut jobs = Vec::with_capacity(inputs.shard_outcomes.len());
    for (shard_idx, smeta) in inputs.shard_outcomes {
        let mut needed = BTreeSet::new();
        for out in &smeta.outcomes {
            for odig in out.outputs.values() {
                needed.insert((StoreTier::PublicCas, odig.sha256, odig.size_bytes));
            }
            for sc in &out.staged_caches {
                let tier = cache_tier(inputs.cache_tiers, &sc.slot)?;
                if winners
                    .get(&(tier, sc.cache_key))
                    .is_some_and(|w| w.check_id == out.check_id)
                {
                    needed.insert((tier, sc.archive_sha256, sc.size_bytes));
                }
            }
        }
        jobs.push(ShardJob {
            index: *shard_idx,
            meta: smeta,
            needed: needed.into_iter().collect(),
        });
    }
    run_shard_jobs(
        &jobs,
        shard_parallelism,
        inputs.artifacts,
        api,
        reg,
        work_dir,
        start,
    )?;

    let mut check_claims = Vec::new();
    for smeta in inputs.shard_outcomes.values() {
        for out in &smeta.outcomes {
            let prov = inputs
                .check_provenance
                .get(&out.check_id)
                .cloned()
                .unwrap_or_default();
            let payload_layers = out
                .outputs
                .iter()
                .map(|(oname, odig)| BlobDescriptor {
                    digest: odig.sha256,
                    size_bytes: odig.size_bytes,
                    media_type: "application/octet-stream".to_owned(),
                    title: Some(oname.as_str().to_owned()),
                })
                .collect();
            let cclaim = Claim::Check {
                action: out.action,
                outputs: out.outputs.clone(),
                provenance_signers: prov,
            };
            check_claims.push(
                StagedClaim::new(StoreTier::PublicCas, &cclaim, payload_layers)
                    .map_err(|e| e.to_string())?,
            );
        }
    }

    let mut cache_claims = Vec::with_capacity(winners.len());
    for ((tier, ckey), w) in &winners {
        let prov = inputs
            .check_provenance
            .get(&w.check_id)
            .cloned()
            .unwrap_or_default();
        let kclaim = Claim::Cache {
            key: *ckey,
            slot: w.slot.clone(),
            archive: w.archive,
            size_bytes: w.size_bytes,
            provenance_signers: prov,
        };
        let payload = vec![BlobDescriptor {
            digest: w.archive,
            size_bytes: w.size_bytes,
            media_type: "application/vnd.ci-core.cache.v1.tar+zstd".to_owned(),
            title: None,
        }];
        cache_claims.push(StagedClaim::new(*tier, &kclaim, payload).map_err(|e| e.to_string())?);
    }

    if !cache_claims.is_empty() || !check_claims.is_empty() {
        sign_and_commit(
            reg,
            sign_batch,
            "cache/check",
            &[],
            &cache_claims,
            &check_claims,
            start,
        )?;
    }

    Ok(PublishSummary {
        images: image_claims.len(),
        caches: cache_claims.len(),
        checks: check_claims.len(),
    })
}

/// Makes image `bmeta.manifest` available at its anchor tag.
fn publish_image(
    recipe: &Sha256Digest,
    bmeta: &BuiltImageMeta,
    artifacts: &[RunArtifactMeta],
    api: &dyn GitHubApi,
    reg: &dyn Registry,
    work_dir: &Path,
    start: Instant,
) -> Result<(), String> {
    let t0 = Instant::now();
    let anchor = LookupTag::image_manifest(&bmeta.manifest);

    // Skip the download when the registry already serves this exact image.
    // `oci_image_anchored` requires that the anchor tag return bytes hashing
    // to `M` and that the config and every layer `M` names be present at
    // their declared sizes. Registry content is addressed by SHA-256, so
    // that is the image a successful push would leave behind, byte for
    // byte, whoever pushed it. Nothing about the claim changes either: the
    // `recipe -> M` binding we sign comes from the gate-verified
    // `img-meta`, not from the `img-blob` artifact, which the full path
    // checks only against that same `M`. Anything short of a full match
    // takes the full path, which verifies the layout locally before
    // uploading.
    let anchored = reg
        .oci_image_anchored(StoreTier::PublicCas, &anchor, &bmeta.manifest)
        .map_err(|e| format!("checking `{anchor}`: {e}"))?;
    if anchored {
        eprintln!(
            "publish: image {}: `{}` already complete in registry, skipped download ({}, total {})",
            recipe.prefix16(),
            anchor.as_str(),
            secs_since(t0),
            secs_since(start),
        );
        return Ok(());
    }

    let art_name = format!("img-blob-a{}-{}", bmeta.attempt, recipe.prefix16());
    let art = find_artifact(artifacts, &art_name)?;
    let zip_path = work_dir.join("cur-img.zip");
    let unzip_dir = work_dir.join("cur-img-unzip");
    let layout_dir = work_dir.join("cur-img-layout");
    api.download_artifact_zip(art.id, &zip_path)
        .map_err(|e| e.to_string())?;
    let downloaded = fs::metadata(&zip_path).map_or(0, |m| m.len());
    let t_download = t0.elapsed();
    extract_zip_archive(&zip_path, &unzip_dir)?;
    let _ = fs::remove_file(&zip_path);
    let t_unzip = t0.elapsed();
    unpack_tar_zst_dir(&unzip_dir.join("oci-image.tar.zst"), &layout_dir)?;
    let _ = fs::remove_dir_all(&unzip_dir);
    let t_unpack = t0.elapsed();

    // `push_untouched_oci_layout` hashes every blob (`verify_oci_layout`,
    // then `upload_verified_blob`) before uploading; `ghcr:` lines break
    // down blobs over 256 MiB.
    let push_res =
        reg.push_untouched_oci_layout(StoreTier::PublicCas, &layout_dir, &bmeta.manifest, &anchor);
    let _ = fs::remove_dir_all(&layout_dir);
    let stats = push_res.map_err(|e| format!("push_untouched_oci_layout `{anchor}`: {e}"))?;
    let t_push = t0.elapsed();
    eprintln!(
        "publish: image {}: downloaded {}, uploaded {} blob(s) ({}), {} already present \
         (download {:.1}s, unzip {:.1}s, unpack {:.1}s, verify+push {:.1}s; total {})",
        recipe.prefix16(),
        human_bytes(downloaded),
        stats.uploaded,
        human_bytes(stats.uploaded_bytes),
        stats.skipped,
        t_download.as_secs_f64(),
        (t_unzip - t_download).as_secs_f64(),
        (t_unpack - t_unzip).as_secs_f64(),
        (t_push - t_unpack).as_secs_f64(),
        secs_since(start),
    );
    Ok(())
}

/// The check whose updated archive is published for one cache key.
struct CacheWinner {
    check_id: CheckId,
    slot: CacheSlotId,
    archive: Sha256Digest,
    size_bytes: u64,
}

/// Picks the lexicographically first updating check per
/// `(StoreTier, CacheKeyDigest)`, so each updated cache key is published once.
fn winning_cache_updaters(
    inputs: &PublishInputs<'_>,
) -> Result<BTreeMap<(StoreTier, Sha256Digest), CacheWinner>, String> {
    let mut winners: BTreeMap<(StoreTier, Sha256Digest), CacheWinner> = BTreeMap::new();
    for smeta in inputs.shard_outcomes.values() {
        for out in &smeta.outcomes {
            for sc in &out.staged_caches {
                let key = (cache_tier(inputs.cache_tiers, &sc.slot)?, sc.cache_key);
                let replace = winners
                    .get(&key)
                    .is_none_or(|prev| out.check_id < prev.check_id);
                if replace {
                    winners.insert(
                        key,
                        CacheWinner {
                            check_id: out.check_id.clone(),
                            slot: sc.slot.clone(),
                            archive: sc.archive_sha256,
                            size_bytes: sc.size_bytes,
                        },
                    );
                }
            }
        }
    }
    Ok(winners)
}

fn cache_tier(
    tiers: &BTreeMap<CacheSlotId, StoreTier>,
    slot: &CacheSlotId,
) -> Result<StoreTier, String> {
    tiers
        .get(slot)
        .copied()
        .ok_or_else(|| format!("cache slot `{slot}` is not configured"))
}

struct ShardJob<'a> {
    index: u32,
    meta: &'a ShardMeta,
    /// Deduplicated `(tier, digest, size)` of every blob its claims name.
    needed: Vec<(StoreTier, Sha256Digest, u64)>,
}

/// Runs `publish_shard_blobs` over `jobs` on up to `parallelism` threads.
/// After the first failure no new job starts; the error of the
/// lowest-indexed failed job is returned.
fn run_shard_jobs(
    jobs: &[ShardJob<'_>],
    parallelism: usize,
    artifacts: &[RunArtifactMeta],
    api: &dyn GitHubApi,
    reg: &dyn Registry,
    work_dir: &Path,
    start: Instant,
) -> Result<(), String> {
    let budget = DiskBudget::new(SHARD_DISK_BUDGET_BYTES);
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let errors: Mutex<BTreeMap<usize, String>> = Mutex::new(BTreeMap::new());
    let workers = parallelism.clamp(1, jobs.len().max(1));
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                while !failed.load(Ordering::SeqCst) {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(job) = jobs.get(i) else {
                        break;
                    };
                    let res =
                        publish_shard_blobs(job, artifacts, api, reg, work_dir, &budget, start);
                    if let Err(e) = res {
                        failed.store(true, Ordering::SeqCst);
                        errors.lock().expect("mutex").insert(i, e);
                    }
                }
            });
        }
    });
    match errors.into_inner().expect("mutex").into_values().next() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Makes every blob in `job.needed` available in the registry.
fn publish_shard_blobs(
    job: &ShardJob<'_>,
    artifacts: &[RunArtifactMeta],
    api: &dyn GitHubApi,
    reg: &dyn Registry,
    work_dir: &Path,
    budget: &DiskBudget,
    start: Instant,
) -> Result<(), String> {
    let t0 = Instant::now();
    let idx = job.index;
    if job.needed.is_empty() {
        eprintln!(
            "publish: shard {idx}: no blobs to publish (total {})",
            secs_since(start)
        );
        return Ok(());
    }

    // A blob the registry already holds with the expected digest and size
    // is the blob we would upload: the registry addresses content by
    // SHA-256, and `upload_verified_blob` would make the same check and
    // transfer nothing. Only the missing blobs need a local copy, and the
    // artifact is downloaded only if at least one is missing.
    let mut missing = Vec::new();
    for &(tier, dig, sz) in &job.needed {
        let present = reg
            .blob_exists(tier, &dig, sz)
            .map_err(|e| format!("checking blob `{dig}`: {e}"))?;
        if !present {
            missing.push((tier, dig, sz));
        }
    }
    let present = job.needed.len() - missing.len();
    if missing.is_empty() {
        eprintln!(
            "publish: shard {idx}: all {present} blob(s) already in registry, skipped download ({}, total {})",
            secs_since(t0),
            secs_since(start),
        );
        return Ok(());
    }

    let art_name = format!("shard-blob-a{}-{idx}", job.meta.attempt);
    let art = find_artifact(artifacts, &art_name)?;
    let payload_bytes: u64 = job
        .meta
        .outcomes
        .iter()
        .flat_map(|o| {
            o.outputs
                .values()
                .map(|d| d.size_bytes)
                .chain(o.staged_caches.iter().map(|c| c.size_bytes))
        })
        .fold(0u64, u64::saturating_add);
    let _lease = budget.acquire(art.size_in_bytes.saturating_add(payload_bytes));

    let dir = work_dir.join(format!("shard-{idx}"));
    let res = (|| -> Result<(u64, u32, u64), String> {
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let zip_path = dir.join("blob.zip");
        let unzip_dir = dir.join("unzip");
        api.download_artifact_zip(art.id, &zip_path)
            .map_err(|e| e.to_string())?;
        let downloaded = fs::metadata(&zip_path).map_or(0, |m| m.len());
        extract_zip_archive(&zip_path, &unzip_dir)?;
        let _ = fs::remove_file(&zip_path);
        let mut uploaded = 0u32;
        let mut uploaded_bytes = 0u64;
        for &(tier, bdig, bsz) in &missing {
            let blob_file = unzip_dir.join(bdig.to_hex());
            let sent = reg
                .upload_verified_blob(tier, &blob_file, &bdig, bsz)
                .map_err(|e| format!("upload_verified_blob `{bdig}`: {e}"))?;
            if sent {
                uploaded += 1;
                uploaded_bytes += bsz;
            }
        }
        Ok((downloaded, uploaded, uploaded_bytes))
    })();
    let _ = fs::remove_dir_all(&dir);
    let (downloaded, uploaded, uploaded_bytes) = res?;
    eprintln!(
        "publish: shard {idx}: downloaded {}, uploaded {uploaded} blob(s) ({}), {} already present ({}, total {})",
        human_bytes(downloaded),
        human_bytes(uploaded_bytes),
        job.needed.len() - uploaded as usize,
        secs_since(t0),
        secs_since(start),
    );
    Ok(())
}

fn sign_and_commit(
    reg: &dyn Registry,
    sign_batch: &mut BatchSigner<'_>,
    label: &str,
    images: &[StagedClaim],
    caches: &[StagedClaim],
    checks: &[StagedClaim],
    start: Instant,
) -> Result<(), String> {
    let mut all = Vec::with_capacity(images.len() + caches.len() + checks.len());
    all.extend_from_slice(images);
    all.extend_from_slice(caches);
    all.extend_from_slice(checks);

    let t0 = Instant::now();
    let bundle = sign_batch(&all)?;
    eprintln!(
        "publish: signed {label} batch over {} claim(s) ({}, total {})",
        all.len(),
        secs_since(t0),
        secs_since(start),
    );

    let t1 = Instant::now();
    commit_claims_bottom_up(reg, &bundle, images, caches, checks).map_err(|e| e.to_string())?;
    eprintln!(
        "publish: committed {label} batch: {} image(s), {} cache(s), {} check(s) ({}, total {})",
        images.len(),
        caches.len(),
        checks.len(),
        secs_since(t1),
        secs_since(start),
    );
    Ok(())
}

fn find_artifact<'a>(
    artifacts: &'a [RunArtifactMeta],
    name: &str,
) -> Result<&'a RunArtifactMeta, String> {
    artifacts
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| format!("missing artifact `{name}`"))
}

fn secs_since(t: Instant) -> String {
    format!("{:.1}s", t.elapsed().as_secs_f64())
}

fn human_bytes(n: u64) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    format!("{:.1} MiB", n as f64 / MIB)
}

/// Counting semaphore over estimated bytes on disk.
struct DiskBudget {
    cap: u64,
    used: Mutex<u64>,
    freed: Condvar,
}

struct DiskLease<'a> {
    budget: &'a DiskBudget,
    bytes: u64,
}

impl DiskBudget {
    fn new(cap: u64) -> Self {
        Self {
            cap,
            used: Mutex::new(0),
            freed: Condvar::new(),
        }
    }

    /// Blocks until `bytes` (clamped to the cap) fit, then reserves them.
    fn acquire(&self, bytes: u64) -> DiskLease<'_> {
        let bytes = bytes.min(self.cap);
        let mut used = self.used.lock().expect("mutex");
        while *used + bytes > self.cap {
            used = self.freed.wait(used).expect("mutex");
        }
        *used += bytes;
        DiskLease {
            budget: self,
            bytes,
        }
    }
}

impl Drop for DiskLease<'_> {
    fn drop(&mut self) {
        *self.budget.used.lock().expect("mutex") -= self.bytes;
        self.budget.freed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs::File;
    use std::io::Write as _;
    use std::path::PathBuf;

    use ci_core_cli::ghcr::InMemoryRegistry;
    use ci_core_model::engine::{CheckExecutionOutcome, StagedCacheUpdate};
    use ci_core_model::store::{GhApiError, MergeQueueSnapshot, PrReview, StoreError};
    use ci_core_model::types::{OutputDigest, OutputName, WorkflowRunMeta};

    use super::*;
    use crate::pack_dir_to_tar_zst;

    /// `GitHubApi` that serves artifact zips from local files and records
    /// every download.
    #[derive(Default)]
    struct FakeArtifactApi {
        files: BTreeMap<u64, PathBuf>,
        downloads: Mutex<Vec<u64>>,
    }

    impl FakeArtifactApi {
        fn downloads(&self) -> Vec<u64> {
            let mut d = self.downloads.lock().unwrap().clone();
            d.sort_unstable();
            d
        }
    }

    impl GitHubApi for FakeArtifactApi {
        fn list_pr_reviews_all(&self, _: u64) -> Result<Vec<PrReview>, GhApiError> {
            Err(GhApiError::Request("unused".to_owned()))
        }
        fn get_merge_queue(&self, _: &str) -> Result<MergeQueueSnapshot, GhApiError> {
            Err(GhApiError::Request("unused".to_owned()))
        }
        fn get_run_metadata(&self, _: u64) -> Result<WorkflowRunMeta, GhApiError> {
            Err(GhApiError::Request("unused".to_owned()))
        }
        fn get_codeowners_errors(&self, _: &GitOid) -> Result<Vec<String>, GhApiError> {
            Err(GhApiError::Request("unused".to_owned()))
        }
        fn list_run_artifacts(
            &self,
            _: u64,
            _: Option<&str>,
        ) -> Result<Vec<RunArtifactMeta>, GhApiError> {
            Err(GhApiError::Request("unused".to_owned()))
        }
        fn download_artifact_zip(&self, artifact_id: u64, dest: &Path) -> Result<(), GhApiError> {
            self.downloads.lock().unwrap().push(artifact_id);
            let src = self
                .files
                .get(&artifact_id)
                .ok_or_else(|| GhApiError::NotFound(artifact_id.to_string()))?;
            fs::copy(src, dest)
                .map(|_| ())
                .map_err(|e| GhApiError::Request(e.to_string()))
        }
    }

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let mut zw = zip::ZipWriter::new(File::create(path).unwrap());
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, bytes) in entries {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(bytes).unwrap();
        }
        zw.finish().unwrap();
    }

    struct Fixture {
        td: tempfile::TempDir,
        built_images: BTreeMap<Sha256Digest, BuiltImageMeta>,
        shard_outcomes: BTreeMap<u32, ShardMeta>,
        check_provenance: BTreeMap<CheckId, BTreeSet<GitOid>>,
        cache_tiers: BTreeMap<CacheSlotId, StoreTier>,
        artifacts: Vec<RunArtifactMeta>,
        artifact_files: BTreeMap<u64, PathBuf>,
        recipe: Sha256Digest,
        manifest: Sha256Digest,
        layer: (Sha256Digest, u64),
        output: (Sha256Digest, u64),
        cache_archive: (Sha256Digest, u64),
        cache_key: Sha256Digest,
        actions: Vec<Sha256Digest>,
    }

    const IMG_ART_ID: u64 = 100;
    const SHARD_ART_BASE: u64 = 200;
    const SHARD_COUNT: u32 = 6;

    /// One built image and `SHARD_COUNT` shards. Shard 0 has a check with
    /// an output blob, shard 1 a check that updates a private cache, and
    /// the other shards checks with no outputs.
    fn fixture() -> Fixture {
        let td = tempfile::tempdir().unwrap();
        let src = td.path().join("src");
        fs::create_dir_all(&src).unwrap();
        let plan_sha256 = Sha256Digest::hash_bytes(b"plan");

        // A minimal pure OCI layout and its `img-blob` artifact.
        let layout = src.join("layout");
        let blobs = layout.join("blobs/sha256");
        fs::create_dir_all(&blobs).unwrap();
        fs::write(
            layout.join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        let cfg_bytes = br#"{"architecture":"amd64","os":"linux","config":{"Env":[]}}"#;
        let cfg_sha = Sha256Digest::hash_bytes(cfg_bytes);
        fs::write(blobs.join(cfg_sha.to_hex()), cfg_bytes).unwrap();
        let layer_bytes = b"layer-tar-payload";
        let layer_sha = Sha256Digest::hash_bytes(layer_bytes);
        fs::write(blobs.join(layer_sha.to_hex()), layer_bytes).unwrap();
        let manifest_bytes = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": cfg_sha.to_oci_digest(),
                "size": cfg_bytes.len()
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": layer_sha.to_oci_digest(),
                "size": layer_bytes.len()
            }]
        }))
        .unwrap();
        let manifest = Sha256Digest::hash_bytes(&manifest_bytes);
        fs::write(blobs.join(manifest.to_hex()), &manifest_bytes).unwrap();
        fs::write(
            layout.join("index.json"),
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "manifests": [{
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": manifest.to_oci_digest(),
                    "size": manifest_bytes.len()
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let tar_zst = src.join("oci-image.tar.zst");
        pack_dir_to_tar_zst(&layout, &tar_zst).unwrap();
        let img_zip = src.join("img.zip");
        write_zip(
            &img_zip,
            &[("oci-image.tar.zst", &fs::read(&tar_zst).unwrap())],
        );

        let recipe = Sha256Digest::hash_bytes(b"recipe");
        let mut built_images = BTreeMap::new();
        built_images.insert(
            recipe,
            BuiltImageMeta {
                plan_sha256,
                attempt: 1,
                recipe,
                manifest,
                verified_config_digest: cfg_sha,
            },
        );
        let mut artifacts = vec![RunArtifactMeta {
            id: IMG_ART_ID,
            name: format!("img-blob-a1-{}", recipe.prefix16()),
            size_in_bytes: fs::metadata(&img_zip).unwrap().len(),
            expired: false,
        }];
        let mut artifact_files = BTreeMap::new();
        artifact_files.insert(IMG_ART_ID, img_zip);

        let output_bytes = b"check output";
        let output = (
            Sha256Digest::hash_bytes(output_bytes),
            output_bytes.len() as u64,
        );
        let cache_bytes = b"cache archive";
        let cache_archive = (
            Sha256Digest::hash_bytes(cache_bytes),
            cache_bytes.len() as u64,
        );
        let cache_key = Sha256Digest::hash_bytes(b"cache key");
        let slot = CacheSlotId::new("cargo").unwrap();
        let mut cache_tiers = BTreeMap::new();
        cache_tiers.insert(slot.clone(), StoreTier::PrivateCache);

        let mut shard_outcomes = BTreeMap::new();
        let mut check_provenance = BTreeMap::new();
        let mut actions = Vec::new();
        for idx in 0..SHARD_COUNT {
            let check_id = CheckId::new(&format!("check-{idx}")).unwrap();
            let action = Sha256Digest::hash_bytes(format!("action-{idx}").as_bytes());
            actions.push(action);
            check_provenance.insert(check_id.clone(), BTreeSet::new());
            let mut outputs = BTreeMap::new();
            let mut staged_caches = Vec::new();
            let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
            if idx == 0 {
                outputs.insert(
                    OutputName::new("out.txt").unwrap(),
                    OutputDigest {
                        sha256: output.0,
                        size_bytes: output.1,
                    },
                );
                entries.push((output.0.to_hex(), output_bytes.to_vec()));
            }
            if idx == 1 {
                staged_caches.push(StagedCacheUpdate {
                    slot: slot.clone(),
                    cache_key,
                    archive_sha256: cache_archive.0,
                    size_bytes: cache_archive.1,
                });
                entries.push((cache_archive.0.to_hex(), cache_bytes.to_vec()));
            }
            shard_outcomes.insert(
                idx,
                ShardMeta {
                    plan_sha256,
                    attempt: 1,
                    shard_index: idx,
                    outcomes: vec![CheckExecutionOutcome {
                        check_id,
                        status: CheckExecStatus::Passed,
                        action,
                        outputs,
                        hydrated_caches: Vec::new(),
                        staged_caches,
                    }],
                    bundles: BTreeMap::new(),
                },
            );
            if !entries.is_empty() {
                let zip_path = src.join(format!("shard-{idx}.zip"));
                let refs: Vec<(&str, &[u8])> = entries
                    .iter()
                    .map(|(n, b)| (n.as_str(), b.as_slice()))
                    .collect();
                write_zip(&zip_path, &refs);
                let id = SHARD_ART_BASE + u64::from(idx);
                artifacts.push(RunArtifactMeta {
                    id,
                    name: format!("shard-blob-a1-{idx}"),
                    size_in_bytes: fs::metadata(&zip_path).unwrap().len(),
                    expired: false,
                });
                artifact_files.insert(id, zip_path);
            }
        }

        Fixture {
            td,
            built_images,
            shard_outcomes,
            check_provenance,
            cache_tiers,
            artifacts,
            artifact_files,
            recipe,
            manifest,
            layer: (layer_sha, layer_bytes.len() as u64),
            output,
            cache_archive,
            cache_key,
            actions,
        }
    }

    impl Fixture {
        fn inputs(&self) -> PublishInputs<'_> {
            PublishInputs {
                built_images: &self.built_images,
                shard_outcomes: &self.shard_outcomes,
                check_provenance: &self.check_provenance,
                cache_tiers: &self.cache_tiers,
                artifacts: &self.artifacts,
            }
        }

        fn api(&self) -> FakeArtifactApi {
            FakeArtifactApi {
                files: self.artifact_files.clone(),
                downloads: Mutex::new(Vec::new()),
            }
        }

        /// A fresh work directory that outlives the run, because
        /// `InMemoryRegistry` keeps image snapshots next to the layout.
        fn work_dir(&self, name: &str) -> PathBuf {
            let p = self.td.path().join(name);
            fs::create_dir_all(&p).unwrap();
            p
        }

        fn image_tag(&self) -> LookupTag {
            LookupTag::image_claim(&self.recipe)
        }

        fn cache_tag(&self) -> LookupTag {
            LookupTag::cache_claim(&self.cache_key)
        }

        fn check_tags(&self) -> Vec<LookupTag> {
            self.actions.iter().map(LookupTag::check_claim).collect()
        }

        fn all_shard_art_ids(&self) -> Vec<u64> {
            vec![SHARD_ART_BASE, SHARD_ART_BASE + 1]
        }
    }

    /// Signer that records the tags of each batch it signs.
    fn recording_signer(
        batches: &RefCell<Vec<Vec<LookupTag>>>,
    ) -> impl FnMut(&[StagedClaim]) -> Result<BlobRef, String> + '_ {
        move |claims: &[StagedClaim]| {
            let mut b = batches.borrow_mut();
            b.push(claims.iter().map(|c| c.tag.clone()).collect());
            Ok(BlobRef::from_bytes(
                format!("bundle-{}", b.len()).into_bytes(),
            ))
        }
    }

    fn run(
        fx: &Fixture,
        api: &FakeArtifactApi,
        reg: &InMemoryRegistry,
        batches: &RefCell<Vec<Vec<LookupTag>>>,
        work: &str,
    ) -> Result<PublishSummary, String> {
        let mut signer = recording_signer(batches);
        publish_verified_outcomes(
            &fx.inputs(),
            api,
            reg,
            &mut signer,
            &fx.work_dir(work),
            SHARD_PARALLELISM,
        )
    }

    #[test]
    fn fresh_publish_commits_images_in_a_batch_before_caches_and_checks() {
        let fx = fixture();
        let api = fx.api();
        let reg = InMemoryRegistry::new();
        let batches = RefCell::new(Vec::new());

        let summary = run(&fx, &api, &reg, &batches, "w").unwrap();
        assert_eq!(
            summary,
            PublishSummary {
                images: 1,
                caches: 1,
                checks: SHARD_COUNT as usize,
            }
        );

        let mut want_downloads = vec![IMG_ART_ID];
        want_downloads.extend(fx.all_shard_art_ids());
        want_downloads.sort_unstable();
        assert_eq!(api.downloads(), want_downloads);

        // Two batches: images alone, then caches and checks.
        let batches = batches.into_inner();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0], vec![fx.image_tag()]);
        let mut want_second = vec![fx.cache_tag()];
        want_second.extend(fx.check_tags());
        assert_eq!(batches[1], want_second);

        // Bottom-up commit order across both batches.
        let anchor = LookupTag::image_manifest(&fx.manifest);
        let mut want_order = vec![
            (StoreTier::PublicCas, anchor),
            (StoreTier::PublicCas, fx.image_tag()),
            (StoreTier::PrivateCache, fx.cache_tag()),
        ];
        want_order.extend(
            fx.check_tags()
                .into_iter()
                .map(|t| (StoreTier::PublicCas, t)),
        );
        assert_eq!(reg.committed_tags_order(), want_order);

        assert!(
            reg.blob_exists(StoreTier::PublicCas, &fx.output.0, fx.output.1)
                .unwrap()
        );
        assert!(
            reg.blob_exists(
                StoreTier::PrivateCache,
                &fx.cache_archive.0,
                fx.cache_archive.1
            )
            .unwrap()
        );
        // The size is part of the existence check.
        assert!(
            !reg.blob_exists(StoreTier::PublicCas, &fx.output.0, fx.output.1 + 1)
                .unwrap()
        );
    }

    #[test]
    fn republish_skips_every_download_already_in_registry() {
        let fx = fixture();
        let reg = InMemoryRegistry::new();
        run(&fx, &fx.api(), &reg, &RefCell::new(Vec::new()), "w1").unwrap();

        // The second run gets no artifact files at all: any download fails.
        let api = FakeArtifactApi::default();
        let batches = RefCell::new(Vec::new());
        let summary = run(&fx, &api, &reg, &batches, "w2").unwrap();
        assert!(api.downloads().is_empty());

        // Claims are still signed and committed, in the same two batches.
        assert_eq!(summary.images, 1);
        assert_eq!(summary.caches, 1);
        assert_eq!(summary.checks, SHARD_COUNT as usize);
        assert_eq!(batches.borrow().len(), 2);
    }

    #[test]
    fn anchor_missing_a_layer_takes_the_full_image_path() {
        let fx = fixture();
        let reg = InMemoryRegistry::new();
        run(&fx, &fx.api(), &reg, &RefCell::new(Vec::new()), "w1").unwrap();
        reg.remove_blob(StoreTier::PublicCas, &fx.layer.0);
        let anchor = LookupTag::image_manifest(&fx.manifest);
        assert!(
            !reg.oci_image_anchored(StoreTier::PublicCas, &anchor, &fx.manifest)
                .unwrap()
        );

        let api = fx.api();
        run(&fx, &api, &reg, &RefCell::new(Vec::new()), "w2").unwrap();
        assert_eq!(api.downloads(), vec![IMG_ART_ID]);
        assert!(
            reg.oci_image_anchored(StoreTier::PublicCas, &anchor, &fx.manifest)
                .unwrap()
        );
    }

    #[test]
    fn shard_with_a_missing_blob_downloads_its_artifact() {
        let fx = fixture();
        let reg = InMemoryRegistry::new();
        run(&fx, &fx.api(), &reg, &RefCell::new(Vec::new()), "w1").unwrap();
        reg.remove_blob(StoreTier::PrivateCache, &fx.cache_archive.0);

        let api = fx.api();
        run(&fx, &api, &reg, &RefCell::new(Vec::new()), "w2").unwrap();
        assert_eq!(api.downloads(), vec![SHARD_ART_BASE + 1]);
        assert!(
            reg.blob_exists(
                StoreTier::PrivateCache,
                &fx.cache_archive.0,
                fx.cache_archive.1
            )
            .unwrap()
        );
    }

    #[test]
    fn image_claims_survive_a_failed_shard_phase() {
        let mut fx = fixture();
        // Shard 0's artifact is missing, so the shard phase fails.
        fx.artifacts.retain(|a| a.id != SHARD_ART_BASE);
        let api = fx.api();
        let reg = InMemoryRegistry::new();
        let batches = RefCell::new(Vec::new());

        let err = run(&fx, &api, &reg, &batches, "w").unwrap_err();
        assert!(err.contains("shard-blob-a1-0"), "{err}");
        assert_eq!(batches.borrow().len(), 1);
        assert!(reg.has_claim(StoreTier::PublicCas, &fx.image_tag()));
        assert!(!reg.has_claim(StoreTier::PrivateCache, &fx.cache_tag()));
        for tag in fx.check_tags() {
            assert!(!reg.has_claim(StoreTier::PublicCas, &tag));
        }
    }

    #[test]
    fn failed_image_batch_stops_before_any_shard_work() {
        let fx = fixture();
        let api = fx.api();
        let reg = InMemoryRegistry::new();
        let mut calls = 0;
        let mut signer = |_: &[StagedClaim]| -> Result<BlobRef, String> {
            calls += 1;
            Err("fulcio unavailable".to_owned())
        };
        let err = publish_verified_outcomes(
            &fx.inputs(),
            &api,
            &reg,
            &mut signer,
            &fx.work_dir("w"),
            SHARD_PARALLELISM,
        )
        .unwrap_err();
        assert_eq!(err, "fulcio unavailable");
        assert_eq!(calls, 1);
        assert_eq!(api.downloads(), vec![IMG_ART_ID]);
        assert!(!reg.has_claim(StoreTier::PublicCas, &fx.image_tag()));
    }

    #[test]
    fn failed_check_is_refused_before_any_side_effect() {
        let mut fx = fixture();
        fx.shard_outcomes.get_mut(&3).unwrap().outcomes[0].status = CheckExecStatus::Failed;
        let api = fx.api();
        let reg = InMemoryRegistry::new();
        let batches = RefCell::new(Vec::new());

        let err = run(&fx, &api, &reg, &batches, "w").unwrap_err();
        assert_eq!(err, "refusing to publish: check `check-3` did not pass");
        assert!(api.downloads().is_empty());
        assert!(batches.borrow().is_empty());
        assert!(reg.committed_tags_order().is_empty());
    }

    #[test]
    fn disk_budget_admits_an_oversized_lease_alone() {
        let budget = DiskBudget::new(10);
        let big = budget.acquire(50);
        assert_eq!(*budget.used.lock().unwrap(), 10);
        drop(big);
        let a = budget.acquire(4);
        let b = budget.acquire(6);
        assert_eq!(*budget.used.lock().unwrap(), 10);
        drop((a, b));
        assert_eq!(*budget.used.lock().unwrap(), 0);
    }

    #[test]
    fn registry_errors_while_checking_presence_are_not_treated_as_absent() {
        // `oci_image_anchored` and `blob_exists` degrade only "not found" and
        // auth failures to `false`; other errors abort `publish`. This keeps
        // a registry outage from silently turning into re-uploads that would
        // fail anyway, and keeps the error visible.
        struct Outage;
        impl Registry for Outage {
            fn fetch_claim_artifact(
                &self,
                _: StoreTier,
                _: &LookupTag,
            ) -> Result<Option<ci_core_model::store::RawClaimArtifact>, StoreError> {
                unreachable!()
            }
            fn head_oci_manifest_by_digest(
                &self,
                _: StoreTier,
                _: &Sha256Digest,
            ) -> Result<bool, StoreError> {
                unreachable!()
            }
            fn fetch_oci_image_by_digest(
                &self,
                _: StoreTier,
                _: &Sha256Digest,
                _: &Path,
            ) -> Result<Sha256Digest, StoreError> {
                unreachable!()
            }
            fn fetch_blob_verified(
                &self,
                _: StoreTier,
                _: &Sha256Digest,
                _: &Path,
                _: u64,
            ) -> Result<u64, StoreError> {
                unreachable!()
            }
            fn push_untouched_oci_layout(
                &self,
                _: StoreTier,
                _: &Path,
                _: &Sha256Digest,
                _: &LookupTag,
            ) -> Result<ci_core_model::store::BlobUploadStats, StoreError> {
                unreachable!()
            }
            fn upload_verified_blob(
                &self,
                _: StoreTier,
                _: &Path,
                _: &Sha256Digest,
                _: u64,
            ) -> Result<bool, StoreError> {
                unreachable!()
            }
            fn blob_exists(
                &self,
                _: StoreTier,
                _: &Sha256Digest,
                _: u64,
            ) -> Result<bool, StoreError> {
                Err(StoreError::Transient("HTTP 503".to_owned()))
            }
            fn oci_image_anchored(
                &self,
                _: StoreTier,
                _: &LookupTag,
                _: &Sha256Digest,
            ) -> Result<bool, StoreError> {
                Err(StoreError::Transient("HTTP 503".to_owned()))
            }
            fn put_claim_artifact(
                &self,
                _: StoreTier,
                _: &LookupTag,
                _: &[u8],
                _: &BlobRef,
                _: &[BlobDescriptor],
            ) -> Result<(), StoreError> {
                unreachable!()
            }
        }

        let fx = fixture();
        let api = fx.api();
        let batches = RefCell::new(Vec::new());
        let mut signer = recording_signer(&batches);
        let err = publish_verified_outcomes(
            &fx.inputs(),
            &api,
            &Outage,
            &mut signer,
            &fx.work_dir("w"),
            SHARD_PARALLELISM,
        )
        .unwrap_err();
        assert!(err.contains("HTTP 503"), "{err}");
        assert!(api.downloads().is_empty());
        assert!(batches.borrow().is_empty());
    }
}
