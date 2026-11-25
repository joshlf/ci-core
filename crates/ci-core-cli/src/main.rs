//! `ci-core` CLI entry point: `plan`, `build-image`, `execute`, `publish`,
//! `gate`, `review-rerun`, `fetch-output`, `run-local`, and `verify-repo`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

use ci_core_cli::ghcr::{GhcrRegistry, normalize_docker_save_to_pure_oci, verify_oci_layout};
use ci_core_cli::git_bare::{
    BareGitSliceReplayer, BareGitTree, HardenedBareGit, LocalWorktree, fetch_codeowners_error_pair,
};
use ci_core_cli::github_api::{GitHubRerunClient, HttpGitHubApi, ObservedRunJob};
use ci_core_cli::sandbox::{
    ContainerRuntime, SandboxLaunchSpec, build_sandbox_env, capture_declared_outputs,
    docker_load_verified_oci_layout, export_rootfs_via_docker, hydrate_cache_archive,
    materialize_work_closure, pack_cache_archive, resolve_bwrap_binary,
    run_cargo_locked_fetch_container, run_cargo_locked_fetch_native, run_container_sandbox,
    run_native_unsandboxed, run_nested_bwrap_sandbox, verify_host_platform,
};
use ci_core_cli::signer::{
    StagedClaim, commit_claims_bottom_up, request_actions_oidc_jwt, sign_batch_claims_online,
};
use ci_core_model::attest::verify_offline;
use ci_core_model::cargo_static::audit_cargo_locked;
use ci_core_model::config::{
    ChecksConfig, ControlPlaneHeader, TreeValidatedConfig, validate_config_against_tree,
};
use ci_core_model::engine::{
    BuiltImageMeta, CheckExecStatus, CheckExecutionOutcome, CompletedRunJobs, EvalStage,
    ExecutionPlan, GatePass, HydratedCacheRecord, ImagePlan, InflightRunAction,
    InflightRunSnapshot, ObservedJobResults, ReviewRerunDecision, ShardMeta, StagedCacheUpdate,
    UpstreamJobResult, build_plan, classify_inflight_run_poll, compute_gc_keep_tags,
    decide_review_rerun, evaluate_gate, resolve_attempt_records, should_attempt_cache_pack,
};
use ci_core_model::store::{BlobDescriptor, GitHubApi, Registry, StoreTier};
use ci_core_model::tcb::{
    PathTrustClass, TcbPlan, caller_allowed, caller_allowed_effective, classify_under_joined_tcb,
    compute_effective_tcb, diff_trees_paths, evaluate_merge_group_tcb, evaluate_pr_tcb,
    has_relevant_review_for_stage2, is_owner_approved, live_tree_authorizes_shadow_pr,
    resolve_effective_control_plane, validate_codeowners, validate_workflows,
    verify_engine_workflows, verify_landed_prefix,
};
use ci_core_model::tree::SourceTree;
use ci_core_model::types::{
    CacheSlotId, CheckId, Claim, GitOid, LocalRunMode, LookupTag, OutputName, RepoRelPath,
    SandboxMode, Sha256Digest, TriggerEvent, UnixSecs, is_valid_git_branch_name,
};

#[derive(Debug, Parser)]
#[command(
    name = "ci-core",
    version,
    about = "Sandboxed CI execution and keyless attestation engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Validate `checks.toml`, workflows, and `.github/CODEOWNERS` statically.
    VerifyRepo {
        #[arg(long, default_value = "ci/checks.toml")]
        config: String,
        #[arg(long)]
        repo_root: Option<PathBuf>,
        #[arg(long)]
        bare_git: Option<PathBuf>,
        #[arg(long)]
        rev: Option<String>,
    },
    /// Compute TCB authorization, GHCR reuse hits, and `<= 256` execution shards.
    Plan {
        #[arg(long, default_value = "ci/checks.toml")]
        config: String,
        #[arg(long, default_value_t = false)]
        gc_keep: bool,
        #[arg(long, default_value_t = false)]
        shadow_mode: bool,
        #[arg(long, default_value_t = false)]
        force_execute_all: bool,
        #[arg(long)]
        event: Option<String>,
        #[arg(long)]
        runtime_ref: Option<String>,
        #[arg(long)]
        base_ref: Option<String>,
        #[arg(long)]
        event_sha: Option<String>,
        #[arg(long)]
        pr_number: Option<u64>,
        #[arg(long)]
        pr_head_sha: Option<String>,
        #[arg(long)]
        merge_group_base_sha: Option<String>,
        #[arg(long)]
        run_id: Option<u64>,
        #[arg(long, default_value_t = 1)]
        run_attempt: u32,
        #[arg(long)]
        bare_git_dir: Option<PathBuf>,
        #[arg(long)]
        remote_url: Option<String>,
        #[arg(long)]
        out_dir: Option<PathBuf>,
        #[arg(long)]
        github_output: Option<PathBuf>,
    },
    /// Build a `PendingBuild` OCI image and emit pure-OCI `img-meta` + `img-blob`.
    BuildImage {
        #[arg(long, default_value = "ci/checks.toml")]
        config: String,
        #[arg(long)]
        plan_dir: PathBuf,
        #[arg(long)]
        recipe: String,
        #[arg(long)]
        run_attempt: u32,
        #[arg(long)]
        bare_git_dir: PathBuf,
        #[arg(long)]
        remote_url: Option<String>,
        #[arg(long)]
        out_meta_dir: PathBuf,
        #[arg(long)]
        out_blob_dir: PathBuf,
    },
    /// Resolve the single winning `img-blob-a<best_A>-<recipe16>` artifact name for a shard.
    ResolveImageBlob {
        #[arg(long)]
        plan_dir: PathBuf,
        #[arg(long)]
        expected_plan_sha256: String,
        #[arg(long)]
        img_meta_root: PathBuf,
        #[arg(long)]
        shard_index: u32,
        #[arg(long)]
        run_attempt: u32,
        #[arg(long)]
        github_output: Option<PathBuf>,
    },
    /// Execute a packed shard inside hermetic `Container` or `NestedBwrap`.
    Execute {
        #[arg(long, default_value = "ci/checks.toml")]
        config: String,
        #[arg(long)]
        plan_dir: PathBuf,
        #[arg(long)]
        expected_plan_sha256: String,
        #[arg(long)]
        img_meta_root: PathBuf,
        #[arg(long)]
        img_blob_dir: Option<PathBuf>,
        #[arg(long)]
        shard_index: u32,
        #[arg(long)]
        run_attempt: u32,
        #[arg(long)]
        bare_git_dir: PathBuf,
        #[arg(long)]
        remote_url: Option<String>,
        #[arg(long)]
        out_meta_dir: PathBuf,
        #[arg(long)]
        out_blob_dir: Option<PathBuf>,
        #[arg(long)]
        github_output: Option<PathBuf>,
    },
    /// Verify `PrePublish`, push verified blobs, mint 1 batch `Bundle0_3`, and commit `m->i->k->a`.
    Publish {
        #[arg(long, default_value = "ci/checks.toml")]
        config: String,
        #[arg(long)]
        plan_dir: PathBuf,
        #[arg(long)]
        expected_plan_sha256: String,
        #[arg(long)]
        img_meta_root: PathBuf,
        #[arg(long)]
        shard_meta_root: PathBuf,
        #[arg(long)]
        run_id: u64,
        #[arg(long)]
        run_attempt: u32,
        #[arg(long)]
        event: String,
        #[arg(long)]
        runtime_ref: String,
        #[arg(long)]
        base_ref: Option<String>,
        #[arg(long)]
        event_sha: String,
        #[arg(long, default_value_t = false)]
        shadow_mode: bool,
        #[arg(long, default_value_t = false)]
        force_execute_all: bool,
        #[arg(long)]
        job_plan_result: String,
        #[arg(long)]
        job_build_images_result: String,
        #[arg(long)]
        job_execute_result: String,
        #[arg(long)]
        bare_git_dir: PathBuf,
        #[arg(long)]
        remote_url: Option<String>,
    },
    /// Compile-time-offline `FinalGate` evaluator (`0` registry calls).
    Gate {
        #[arg(long, default_value = "ci/checks.toml")]
        config: String,
        #[arg(long)]
        plan_dir: PathBuf,
        #[arg(long)]
        expected_plan_sha256: String,
        #[arg(long)]
        img_meta_root: PathBuf,
        #[arg(long)]
        shard_meta_root: PathBuf,
        #[arg(long)]
        run_id: u64,
        #[arg(long)]
        run_attempt: u32,
        #[arg(long, num_args = 0..=1, default_missing_value = "true", default_value_t = false)]
        cancelled: bool,
        #[arg(long)]
        event: String,
        #[arg(long)]
        runtime_ref: String,
        #[arg(long)]
        base_ref: Option<String>,
        #[arg(long)]
        event_sha: String,
        #[arg(long)]
        pr_head_sha: Option<String>,
        #[arg(long, default_value_t = false)]
        shadow_mode: bool,
        #[arg(long, default_value_t = false)]
        force_execute_all: bool,
        #[arg(long)]
        job_plan_result: String,
        #[arg(long)]
        job_build_images_result: String,
        #[arg(long)]
        job_execute_result: String,
        #[arg(long)]
        job_publish_result: String,
        #[arg(long)]
        bare_git_dir: PathBuf,
        #[arg(long)]
        remote_url: Option<String>,
    },
    /// Fork-safe Stage-2 `workflow_run` review rerunner (`0` PR checkout, `0` cancel calls).
    ReviewRerun {
        #[arg(long, default_value = "ci/checks.toml")]
        config: String,
        #[arg(long)]
        signal_conclusion: String,
        #[arg(long)]
        head_sha: String,
        #[arg(long)]
        bare_git_dir: PathBuf,
        #[arg(long)]
        remote_url: Option<String>,
    },
    /// Verify and download a declared check output from GHCR for `<rev>`.
    FetchOutput {
        #[arg(long, default_value = "ci/checks.toml")]
        config: String,
        #[arg(long, default_value = "HEAD")]
        rev: String,
        #[arg(long)]
        check: String,
        #[arg(long)]
        output: String,
        #[arg(long)]
        dest: PathBuf,
        #[arg(long)]
        worktree: Option<PathBuf>,
        #[arg(long)]
        bare_git_dir: Option<PathBuf>,
        #[arg(long)]
        remote_url: Option<String>,
    },
    /// Reproduce a single check locally in `Container`, `NestedBwrap`, or `--native`.
    RunLocal {
        #[arg(long, default_value = "ci/checks.toml")]
        config: String,
        #[arg(long)]
        check: String,
        #[arg(long, default_value = ".")]
        repo_root: PathBuf,
        #[arg(long, default_value_t = false)]
        native: bool,
        #[arg(long, default_value_t = false)]
        cold: bool,
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
}

fn now_unix_secs() -> UnixSecs {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    UnixSecs(secs)
}

fn parse_trigger_event(s: &str) -> Result<TriggerEvent, String> {
    match s {
        "pull_request" => Ok(TriggerEvent::PullRequest),
        "merge_group" => Ok(TriggerEvent::MergeGroup),
        "push" => Ok(TriggerEvent::Push),
        other => Err(format!("unsupported trigger event {other:?}")),
    }
}

fn parse_job_result(s: &str) -> Result<UpstreamJobResult, String> {
    match s {
        "success" => Ok(UpstreamJobResult::Success),
        "failure" => Ok(UpstreamJobResult::Failure),
        "skipped" => Ok(UpstreamJobResult::Skipped),
        "cancelled" => Ok(UpstreamJobResult::Cancelled),
        other => Err(format!("unknown job result {other:?}")),
    }
}

fn load_cfg_from_tree(
    tree: &dyn SourceTree,
    config_path: &RepoRelPath,
) -> Result<(ChecksConfig, Sha256Digest), String> {
    let bytes = tree
        .read_blob(config_path)
        .map_err(|e| format!("failed to read `{config_path}`: {e}"))?;
    let sha = Sha256Digest::hash_bytes(&bytes);
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| format!("invalid UTF-8 in `{config_path}`: {e}"))?;
    let cfg = ChecksConfig::parse_toml(text, config_path)
        .map_err(|e| format!("invalid `{config_path}`: {e}"))?;
    Ok((cfg, sha))
}

fn load_optional_cfg_from_tree(
    tree: &dyn SourceTree,
    config_path: &RepoRelPath,
) -> Result<Option<(ChecksConfig, Sha256Digest)>, String> {
    if tree
        .kind_of(config_path)
        .map_err(|e| format!("failed to inspect `{config_path}`: {e}"))?
        .is_none()
    {
        return Ok(None);
    }
    load_cfg_from_tree(tree, config_path).map(Some)
}

fn resolve_live_cfg_for_event(
    event: TriggerEvent,
    live_tree: &BareGitTree,
    target_cfg: &ChecksConfig,
    config_path: &RepoRelPath,
) -> Result<(ChecksConfig, bool), String> {
    match load_optional_cfg_from_tree(live_tree, config_path)? {
        Some((cfg, _)) => Ok((cfg, true)),
        None if event != TriggerEvent::Push => Ok((target_cfg.clone(), false)),
        None => Err(format!(
            "default_branch lacks `{config_path}` on Push event"
        )),
    }
}

/// Resolves the landed base `B` (`S_0`) of a `merge_group` chain.
///
/// GitHub sets `merge_group.base_sha` to the group's parent commit. For the
/// entry at the head of the queue that parent is `H_default`, or an ancestor
/// of it once later commits have landed. For an entry queued behind others,
/// the parent is the previous entry's not-yet-landed commit, so `H_default`
/// is instead a first-parent ancestor of the parent. In that case the chain
/// starts at `H_default`, and the queued-ahead entries become chain steps that
/// `evaluate_merge_group_tcb` attributes through merge-queue replay. Any other
/// relationship fails closed.
fn resolve_merge_group_base(
    git: &HardenedBareGit,
    mg_parent: &GitOid,
    h_default_sha: &GitOid,
) -> Result<GitOid, String> {
    // Test both directions on local history first, and deepen both tips in
    // lockstep only while neither holds, so a queued entry does not unshallow
    // the default branch looking for an ancestry that runs the other way.
    let mut depth = 32u32;
    let queued_behind = loop {
        if git.object_exists(mg_parent) && git.object_exists(h_default_sha) {
            let (p, h) = (mg_parent.to_hex(), h_default_sha.to_hex());
            if git.is_ancestor(&p, &h).map_err(|e| e.to_string())? {
                break false;
            }
            if git.is_ancestor(&h, &p).map_err(|e| e.to_string())? {
                break true;
            }
        }
        if !git.has_remote() || depth > 65_536 {
            return Err(format!(
                "merge_group parent `{mg_parent}` and default branch `{h_default_sha}` are \
                 unrelated"
            ));
        }
        git.fetch_oid(mg_parent, depth).map_err(|e| e.to_string())?;
        git.fetch_oid(h_default_sha, depth)
            .map_err(|e| e.to_string())?;
        depth = depth.saturating_mul(4);
    };
    if !queued_behind {
        return Ok(*mg_parent);
    }
    let queued_ahead = git
        .first_parent_chain(h_default_sha, mg_parent)
        .map_err(|e| e.to_string())?;
    let mut prev = *h_default_sha;
    for c in &queued_ahead {
        let parents = git.commit_parents(c).map_err(|e| e.to_string())?;
        if parents.first() != Some(&prev) {
            return Err(format!(
                "default branch `{h_default_sha}` is not on the first-parent chain of \
                 merge_group parent `{mg_parent}`"
            ));
        }
        prev = *c;
    }
    if prev != *mg_parent {
        return Err(format!(
            "first-parent chain from `{h_default_sha}` does not end at merge_group parent \
             `{mg_parent}`"
        ));
    }
    Ok(*h_default_sha)
}

fn resolve_pr_tcb_base(
    git: &HardenedBareGit,
    eff_remote: Option<&str>,
    default_branch: &str,
    h_default_sha: &GitOid,
    base_ref: Option<&str>,
    event_sha: &GitOid,
    pr_first_parent: &GitOid,
) -> Result<GitOid, String> {
    let br = base_ref
        .ok_or_else(|| "pull_request requires non-empty --base-ref / GITHUB_BASE_REF".to_owned())?;
    if !is_valid_git_branch_name(br) {
        return Err(format!("invalid pull_request base_ref {br:?}"));
    }
    if br == default_branch {
        git.ensure_ancestor_with_deepening(pr_first_parent, &h_default_sha.to_hex())
            .map_err(|e| e.to_string())?;
        Ok(*pr_first_parent)
    } else {
        let base_branch_ref = format!("refs/heads/{br}");
        let pr_base_tip = if eff_remote.is_some() {
            git.fetch_ref(&base_branch_ref, "refs/ci-core/pr-base", 32)
                .map_err(|e| e.to_string())?
        } else {
            git.rev_parse_oid(&base_branch_ref)
                .map_err(|e| e.to_string())?
        };
        git.ensure_ancestor_with_deepening(pr_first_parent, &pr_base_tip.to_hex())
            .map_err(|e| e.to_string())?;
        git.merge_base_with_deepening(h_default_sha, event_sha)
            .map_err(|e| e.to_string())
    }
}

fn runtime_repo_identity(live_cfg: &ChecksConfig) -> Result<(String, u64), String> {
    let repo_slug = std::env::var("GITHUB_REPOSITORY")
        .unwrap_or_else(|_| live_cfg.repo.slug.canonical().to_owned());
    let repo_id = match std::env::var("GITHUB_REPOSITORY_ID") {
        Ok(s) if !s.trim().is_empty() => s
            .trim()
            .parse::<u64>()
            .map_err(|e| format!("invalid GITHUB_REPOSITORY_ID {s:?}: {e}"))?,
        _ => live_cfg.repo.id,
    };
    if !repo_slug.eq_ignore_ascii_case(live_cfg.repo.slug.canonical()) {
        return Err(format!(
            "GITHUB_REPOSITORY {repo_slug:?} does not match checks.toml slug {:?}",
            live_cfg.repo.slug.canonical()
        ));
    }
    if repo_id != live_cfg.repo.id {
        return Err(format!(
            "GITHUB_REPOSITORY_ID {repo_id} != checks.toml repo.id {}",
            live_cfg.repo.id
        ));
    }
    Ok((repo_slug, repo_id))
}

fn gh_token_from_env() -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

fn ghcr_token_from_env() -> Option<String> {
    std::env::var("CI_CORE_GHCR_TOKEN")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(gh_token_from_env)
}

fn default_remote_url_from_env() -> Option<String> {
    let slug = std::env::var("GITHUB_REPOSITORY").ok()?;
    let server =
        std::env::var("GITHUB_SERVER_URL").unwrap_or_else(|_| "https://github.com".to_owned());
    Some(format!("{}/{}.git", server.trim_end_matches('/'), slug))
}

fn read_bundles_dir(bundles_dir: &Path) -> Result<BTreeMap<Sha256Digest, Vec<u8>>, String> {
    let mut map = BTreeMap::new();
    if !bundles_dir.is_dir() {
        return Ok(map);
    }
    for ent_res in fs::read_dir(bundles_dir).map_err(|e| e.to_string())? {
        let ent = ent_res.map_err(|e| e.to_string())?;
        let p = ent.path();
        if !p.is_file() {
            continue;
        }
        let bytes = fs::read(&p).map_err(|e| e.to_string())?;
        let sha = Sha256Digest::hash_bytes(&bytes);
        map.insert(sha, bytes);
    }
    Ok(map)
}

fn collect_json_files_named<T: serde::de::DeserializeOwned>(
    root: &Path,
    filename: &str,
) -> Result<Vec<T>, String> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    fn walk<T: serde::de::DeserializeOwned>(
        cur: &Path,
        filename: &str,
        out: &mut Vec<T>,
    ) -> Result<(), String> {
        for ent_res in fs::read_dir(cur).map_err(|e| e.to_string())? {
            let ent = ent_res.map_err(|e| e.to_string())?;
            let p = ent.path();
            let meta = fs::symlink_metadata(&p).map_err(|e| e.to_string())?;
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.file_type().is_dir() {
                walk(&p, filename, out)?;
            } else if meta.file_type().is_file()
                && p.file_name().and_then(|n| n.to_str()) == Some(filename)
            {
                let bytes = fs::read(&p).map_err(|e| e.to_string())?;
                let parsed: T = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("failed to parse `{}`: {e}", p.display()))?;
                out.push(parsed);
            }
        }
        Ok(())
    }
    walk(root, filename, &mut out)?;
    Ok(out)
}

fn unpack_tar_zst_dir(archive_file: &Path, dest_dir: &Path) -> Result<(), String> {
    if dest_dir.exists() {
        fs::remove_dir_all(dest_dir).map_err(|e| e.to_string())?;
    }
    fs::create_dir_all(dest_dir).map_err(|e| e.to_string())?;
    let f = File::open(archive_file).map_err(|e| e.to_string())?;
    let dec = zstd::Decoder::new(f).map_err(|e| e.to_string())?;
    let mut ar = tar::Archive::new(dec);
    ar.set_preserve_permissions(false);
    ar.unpack(dest_dir).map_err(|e| e.to_string())
}

fn pack_dir_to_tar_zst(src_dir: &Path, archive_file: &Path) -> Result<(), String> {
    if let Some(p) = archive_file.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let f = File::create(archive_file).map_err(|e| e.to_string())?;
    let enc = zstd::Encoder::new(f, 3).map_err(|e| e.to_string())?;
    let mut tb = tar::Builder::new(enc);
    tb.follow_symlinks(false);
    tb.append_dir_all(".", src_dir).map_err(|e| e.to_string())?;
    let enc = tb.into_inner().map_err(|e| e.to_string())?;
    let out = enc.finish().map_err(|e| e.to_string())?;
    out.sync_all().map_err(|e| e.to_string())
}

fn extract_zip_archive(zip_path: &Path, dest_dir: &Path) -> Result<(), String> {
    if dest_dir.exists() {
        fs::remove_dir_all(dest_dir).map_err(|e| e.to_string())?;
    }
    fs::create_dir_all(dest_dir).map_err(|e| e.to_string())?;
    let zip_file = File::open(zip_path).map_err(|e| format!("failed to open zip: {e}"))?;
    let mut archive =
        zip::ZipArchive::new(zip_file).map_err(|e| format!("invalid zip archive: {e}"))?;
    // Cap total decompressed bytes per GitHub artifact zip at 4 GiB to defend
    // against zip bombs while comfortably covering multi-blob shard artifacts.
    const MAX_ZIP_EXTRACT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
    let mut total_bytes: u64 = 0;

    for idx in 0..archive.len() {
        let mut entry = archive
            .by_index(idx)
            .map_err(|e| format!("zip entry {idx} failed: {e}"))?;
        if entry.is_symlink() {
            return Err(format!(
                "zip entry {:?} is a symlink (forbidden in CI artifacts)",
                entry.name()
            ));
        }
        let enclosed = entry
            .enclosed_name()
            .ok_or_else(|| format!("zip entry {:?} escapes destination root", entry.name()))?;
        let segs_owned: Vec<String> = enclosed
            .components()
            .map(|c| {
                c.as_os_str()
                    .to_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "non-UTF-8 path inside artifact zip".to_owned())
            })
            .collect::<Result<_, _>>()?;
        let segs: Vec<&str> = segs_owned.iter().map(String::as_str).collect();
        if segs.is_empty() {
            continue;
        }
        if entry.is_dir() {
            ci_core_cli::sandbox::open_or_create_dir_nofollow(dest_dir, &segs)
                .map_err(|e| e.to_string())?;
            continue;
        }
        let (parent_segs, leaf) = segs.split_at(segs.len() - 1);
        let parent_fd = ci_core_cli::sandbox::open_or_create_dir_nofollow(dest_dir, parent_segs)
            .map_err(|e| e.to_string())?;
        let out_fd = rustix::fs::openat(
            &parent_fd,
            leaf[0],
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::from_raw_mode(0o644),
        )
        .map_err(|e| format!("openat create zip member `{}`: {e}", enclosed.display()))?;
        let mut out_f = File::from(out_fd);
        let remaining = MAX_ZIP_EXTRACT_BYTES.saturating_sub(total_bytes);
        let mut limited = std::io::Read::take(&mut entry, remaining.saturating_add(1));
        let written = std::io::copy(&mut limited, &mut out_f)
            .map_err(|e| format!("extract zip member `{}`: {e}", enclosed.display()))?;
        total_bytes = total_bytes.saturating_add(written);
        if total_bytes > MAX_ZIP_EXTRACT_BYTES {
            return Err("artifact zip exceeded 4 GiB decompression limit".to_owned());
        }
        out_f.sync_all().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    for ent_res in fs::read_dir(src).map_err(|e| e.to_string())? {
        let ent = ent_res.map_err(|e| e.to_string())?;
        let sp = ent.path();
        let dp = dst.join(ent.file_name());
        let meta = fs::symlink_metadata(&sp).map_err(|e| e.to_string())?;
        if meta.file_type().is_dir() {
            copy_dir_recursive(&sp, &dp)?;
        } else if meta.file_type().is_file() {
            fs::copy(&sp, &dp).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn evaluate_event_commit_policy(
    git: &HardenedBareGit,
    target_cfg: &ChecksConfig,
    event: TriggerEvent,
    event_sha: &GitOid,
    pr_parents: Option<(GitOid, GitOid)>,
    mg_chain_commits: Option<&[GitOid]>,
) -> Result<(), String> {
    if target_cfg.commit_policy.forbid_message_regex.is_none() {
        return Ok(());
    }
    let commit_oids: Vec<GitOid> = match event {
        TriggerEvent::PullRequest => {
            let (base_sha, pr_head_sha) = pr_parents
                .ok_or_else(|| "missing PR parents for commit_policy evaluation".to_owned())?;
            git.merge_base_with_deepening(&base_sha, &pr_head_sha)
                .map_err(|e| e.to_string())?;
            git.rev_list_range(&base_sha, &pr_head_sha)
                .map_err(|e| e.to_string())?
        }
        TriggerEvent::MergeGroup => mg_chain_commits
            .ok_or_else(|| "missing merge_group commits for commit_policy evaluation".to_owned())?
            .to_vec(),
        TriggerEvent::Push => vec![*event_sha],
    };
    let mut pairs = Vec::with_capacity(commit_oids.len());
    for oid in commit_oids {
        let msg = git.commit_message(&oid).map_err(|e| e.to_string())?;
        pairs.push((oid, msg));
    }
    target_cfg.validate_commit_messages(&pairs)
}

fn cmd_verify_repo(
    config_rel: &str,
    repo_root: Option<PathBuf>,
    bare_git: Option<PathBuf>,
    rev: Option<String>,
) -> Result<(), String> {
    let config_path = RepoRelPath::new(config_rel).map_err(|e| e.to_string())?;
    let tree_box: Box<dyn SourceTree> = if let Some(bg) = bare_git {
        let git = HardenedBareGit::open_existing(bg).map_err(|e| e.to_string())?;
        let rev_str = rev.as_deref().unwrap_or("HEAD");
        let oid = git.rev_parse_oid(rev_str).map_err(|e| e.to_string())?;
        Box::new(BareGitTree::from_commit(git, &oid).map_err(|e| e.to_string())?)
    } else {
        let root = repo_root.unwrap_or_else(|| PathBuf::from("."));
        Box::new(LocalWorktree::new(root).map_err(|e| e.to_string())?)
    };

    let (cfg, _) = load_cfg_from_tree(tree_box.as_ref(), &config_path)?;
    let validated = validate_config_against_tree(&cfg, tree_box.as_ref())
        .map_err(|e| format!("tree/Cargo validation failed: {e}"))?;
    validate_workflows(tree_box.as_ref(), &cfg).map_err(|e| e.to_string())?;
    validate_codeowners(tree_box.as_ref(), &cfg, &config_path).map_err(|e| e.to_string())?;

    println!(
        "verify-repo passed: repo=`{}` images={} caches={} expanded_checks={}",
        cfg.repo.slug,
        validated.image_closures.len(),
        validated.cache_closures.len(),
        validated.check_closures.len()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_plan(
    config_rel: &str,
    gc_keep: bool,
    shadow_mode: bool,
    force_execute_all: bool,
    event_arg: Option<String>,
    runtime_ref_arg: Option<String>,
    base_ref_arg: Option<String>,
    event_sha_arg: Option<String>,
    pr_number_arg: Option<u64>,
    pr_head_sha_arg: Option<String>,
    mg_base_sha_arg: Option<String>,
    run_id_arg: Option<u64>,
    run_attempt: u32,
    bare_git_dir: Option<PathBuf>,
    remote_url: Option<String>,
    out_dir: Option<PathBuf>,
    github_output: Option<PathBuf>,
) -> Result<(), String> {
    let config_path = RepoRelPath::new(config_rel).map_err(|e| e.to_string())?;
    let git_dir = bare_git_dir.unwrap_or_else(|| std::env::temp_dir().join("ci-core-bare.git"));
    let eff_remote = remote_url.or_else(default_remote_url_from_env);
    let git = HardenedBareGit::init_bare(&git_dir, eff_remote.clone(), gh_token_from_env())
        .map_err(|e| e.to_string())?;

    if gc_keep {
        let head_oid = if eff_remote.is_some() {
            git.fetch_ref("HEAD", "refs/ci-core/default", 1)
                .map_err(|e| e.to_string())?
        } else {
            git.rev_parse_oid("HEAD").map_err(|e| e.to_string())?
        };
        let tree = BareGitTree::from_commit(git, &head_oid).map_err(|e| e.to_string())?;
        let (cfg, cfg_sha) = load_cfg_from_tree(&tree, &config_path)?;
        let validated = validate_config_against_tree(&cfg, &tree).map_err(|e| e.to_string())?;
        let reg = GhcrRegistry::new(
            &cfg.repo.slug,
            &cfg.repo.effective_cas_repo(),
            &cfg.repo.effective_cache_repo(),
            ghcr_token_from_env(),
        )
        .map_err(|e| e.to_string())?;
        let (plan, _) = build_plan(
            1,
            now_unix_secs(),
            TriggerEvent::Push,
            false,
            false,
            format!("refs/heads/{}", cfg.repo.default_branch),
            None,
            head_oid,
            None,
            true,
            cfg_sha,
            cfg_sha,
            None,
            TcbPlan::NotRequired,
            &cfg.repo.signer_policy().map_err(|e| e.to_string())?,
            &cfg,
            &validated,
            &reg,
        )?;
        for tag in compute_gc_keep_tags(&plan) {
            println!("{tag}");
        }
        return Ok(());
    }

    let event_s = event_arg
        .or_else(|| std::env::var("GITHUB_EVENT_NAME").ok())
        .ok_or_else(|| "missing --event / GITHUB_EVENT_NAME".to_owned())?;
    let event = parse_trigger_event(&event_s)?;
    let runtime_ref = runtime_ref_arg
        .or_else(|| std::env::var("GITHUB_REF").ok())
        .ok_or_else(|| "missing --runtime-ref / GITHUB_REF".to_owned())?;
    let base_ref = base_ref_arg
        .or_else(|| std::env::var("GITHUB_BASE_REF").ok())
        .filter(|s| !s.is_empty());
    let event_sha_s = event_sha_arg
        .or_else(|| std::env::var("GITHUB_SHA").ok())
        .ok_or_else(|| "missing --event-sha / GITHUB_SHA".to_owned())?;
    let event_sha = GitOid::from_hex(&event_sha_s).map_err(|e| e.to_string())?;
    let run_id = run_id_arg
        .or_else(|| std::env::var("GITHUB_RUN_ID").ok()?.parse().ok())
        .ok_or_else(|| "missing --run-id / GITHUB_RUN_ID".to_owned())?;

    // Fetch `event_sha` first to discover `default_branch` if needed, then fetch
    // authoritative `refs/heads/{default_branch}` (`H_default`).
    let initial_depth = match event {
        TriggerEvent::PullRequest => 2,
        TriggerEvent::MergeGroup => 32,
        TriggerEvent::Push => 1,
    };
    if eff_remote.is_some() {
        git.fetch_oid(&event_sha, initial_depth)
            .map_err(|e| e.to_string())?;
    }
    let event_tree =
        BareGitTree::from_commit(git.clone(), &event_sha).map_err(|e| e.to_string())?;
    let (target_cfg, candidate_cfg_sha256) = load_cfg_from_tree(&event_tree, &config_path)?;
    let def_branch_ref = format!("refs/heads/{}", target_cfg.repo.default_branch);
    let mut h_default_sha = if eff_remote.is_some() {
        git.fetch_ref(&def_branch_ref, "refs/ci-core/default", 32)
            .map_err(|e| e.to_string())?
    } else {
        git.rev_parse_oid(&def_branch_ref)
            .map_err(|e| e.to_string())?
    };
    let mut live_tree =
        BareGitTree::from_commit(git.clone(), &h_default_sha).map_err(|e| e.to_string())?;
    let (mut live_cfg, mut live_onboarded) =
        resolve_live_cfg_for_event(event, &live_tree, &target_cfg, &config_path)?;

    let (_rt_slug, _rt_id) = runtime_repo_identity(&live_cfg)?;
    if !target_cfg.repo.same_identity(&live_cfg.repo) {
        return Err("target_cfg [repo] identity diverged from live_cfg [repo]".to_owned());
    }

    if live_onboarded {
        validate_workflows(&live_tree, &live_cfg).map_err(|e| e.to_string())?;
        validate_codeowners(&live_tree, &live_cfg, &config_path).map_err(|e| e.to_string())?;
    }

    let api = HttpGitHubApi::new(live_cfg.repo.slug.clone(), gh_token_from_env(), None)
        .map_err(|e| e.to_string())?;
    let observed_run = api.get_run_metadata(run_id).map_err(|e| e.to_string())?;

    let mut second_parent: Option<GitOid> = None;
    let mut pr_parents_pair: Option<(GitOid, GitOid)> = None;
    let mut mg_s_chain_commits: Option<Vec<GitOid>> = None;
    let mut base_cfg_sha256 = candidate_cfg_sha256;
    let mut merge_group_chain_trees: Option<(GitOid, Vec<GitOid>)> = None;
    let publish_eligible: bool;

    let tcb_plan = match event {
        TriggerEvent::PullRequest => {
            publish_eligible = false;
            let pr_number =
                pr_number_arg.ok_or_else(|| "pull_request requires --pr-number".to_owned())?;
            let pr_head_sha = GitOid::from_hex(
                pr_head_sha_arg
                    .as_deref()
                    .ok_or_else(|| "pull_request requires --pr-head-sha".to_owned())?,
            )
            .map_err(|e| e.to_string())?;

            let parents = git.commit_parents(&event_sha).map_err(|e| e.to_string())?;
            if parents.len() != 2 || parents[1] != pr_head_sha {
                return Err(format!(
                    "pull_request merge commit `{event_sha}` parents {parents:?} do not match pr_head_sha `{pr_head_sha}`"
                ));
            }
            let base_sha = parents[0];
            second_parent = Some(parents[1]);
            pr_parents_pair = Some((base_sha, pr_head_sha));
            let tcb_base_sha = resolve_pr_tcb_base(
                &git,
                eff_remote.as_deref(),
                &live_cfg.repo.default_branch,
                &h_default_sha,
                base_ref.as_deref(),
                &event_sha,
                &base_sha,
            )?;

            let tcb_base_tree =
                BareGitTree::from_commit(git.clone(), &tcb_base_sha).map_err(|e| e.to_string())?;
            let (base_cfg, b_sha) = match load_optional_cfg_from_tree(&tcb_base_tree, &config_path)?
            {
                Some(pair) => pair,
                None => (target_cfg.clone(), Sha256Digest::hash_bytes(&[])),
            };
            base_cfg_sha256 = b_sha;
            let reviews = api
                .list_pr_reviews_all(pr_number)
                .map_err(|e| e.to_string())?;
            let live_cp = live_cfg.control_plane();
            let caller_or_engine_blocked_under_live =
                !caller_allowed(&live_cp.caller, event, &observed_run)
                    || verify_engine_workflows(
                        &observed_run.referenced_workflows,
                        &live_cp.signer,
                        event,
                    )
                    .is_err();
            evaluate_pr_tcb(
                &config_path,
                &live_cfg,
                &base_cfg,
                &target_cfg,
                &tcb_base_tree,
                &event_tree,
                pr_number,
                pr_head_sha,
                &reviews,
                caller_or_engine_blocked_under_live,
            )
            .map_err(|e| e.to_string())?
        }
        TriggerEvent::MergeGroup => {
            publish_eligible = true;
            let expected_prefix = format!(
                "refs/heads/gh-readonly-queue/{}/",
                live_cfg.repo.default_branch
            );
            if !runtime_ref.starts_with(&expected_prefix)
                || runtime_ref.len() == expected_prefix.len()
            {
                return Err(format!(
                    "merge_group ref {runtime_ref:?} does not match {expected_prefix:?}"
                ));
            }
            let mg_parent = GitOid::from_hex(
                mg_base_sha_arg
                    .as_deref()
                    .ok_or_else(|| "merge_group requires --merge-group-base-sha".to_owned())?,
            )
            .map_err(|e| e.to_string())?;
            git.ensure_ancestor_with_deepening(&mg_parent, &event_sha.to_hex())
                .map_err(|e| e.to_string())?;
            let b_sha = resolve_merge_group_base(&git, &mg_parent, &h_default_sha)?;

            let b_tree =
                BareGitTree::from_commit(git.clone(), &b_sha).map_err(|e| e.to_string())?;
            base_cfg_sha256 = match load_optional_cfg_from_tree(&b_tree, &config_path)? {
                Some((_, b_cfg_sha)) => b_cfg_sha,
                None => Sha256Digest::hash_bytes(&[]),
            };

            let s_chain = git
                .first_parent_chain(&b_sha, &event_sha)
                .map_err(|e| e.to_string())?;
            if s_chain.is_empty() {
                return Err("merge_group first-parent chain B..E is empty".to_owned());
            }
            let mut full_commits = Vec::with_capacity(1 + s_chain.len());
            full_commits.push(b_sha);
            full_commits.extend_from_slice(&s_chain);
            mg_s_chain_commits = Some(s_chain.clone());

            let mut chain_owned_trees = Vec::with_capacity(full_commits.len());
            let mut chain_tree_oids = Vec::with_capacity(full_commits.len());
            for c in &full_commits {
                let bt = BareGitTree::from_commit(git.clone(), c).map_err(|e| e.to_string())?;
                chain_tree_oids.push(bt.tree_oid());
                chain_owned_trees.push(bt);
            }
            merge_group_chain_trees = Some((chain_tree_oids[0], chain_tree_oids[1..].to_vec()));

            let run_mg_attempt =
                |cur_live_cfg: &ChecksConfig, cur_h_def: &GitOid| -> Result<TcbPlan, String> {
                    let m_chain = git
                        .first_parent_chain(&b_sha, cur_h_def)
                        .map_err(|e| e.to_string())?;
                    let mut landed_oids = Vec::with_capacity(1 + m_chain.len());
                    landed_oids.push(chain_tree_oids[0]);
                    for mc in &m_chain {
                        landed_oids.push(git.commit_tree_oid(mc).map_err(|e| e.to_string())?);
                    }
                    let mq = api
                        .get_merge_queue(&cur_live_cfg.repo.default_branch)
                        .map_err(|e| e.to_string())?;
                    for ent in &mq.entries {
                        if eff_remote.is_some() {
                            let _ = git.fetch_oid(&ent.head_oid, 32);
                        }
                    }
                    let tree_refs: Vec<&dyn SourceTree> = chain_owned_trees
                        .iter()
                        .map(|t| t as &dyn SourceTree)
                        .collect();
                    let replayer = BareGitSliceReplayer::new(
                        &git,
                        mq.merge_method,
                        &full_commits,
                        &chain_tree_oids,
                    );
                    evaluate_merge_group_tcb(
                        &config_path,
                        cur_live_cfg,
                        &tree_refs,
                        &chain_tree_oids,
                        &landed_oids,
                        &mq.entries,
                        &replayer,
                        &|pr_n| api.list_pr_reviews_all(pr_n).map_err(|e| e.to_string()),
                    )
                    .map_err(|e| e.to_string())
                };

            match run_mg_attempt(&live_cfg, &h_default_sha) {
                Ok(tp) => tp,
                Err(_) if eff_remote.is_some() => {
                    // Single fresh `H_default` retry on concurrent merge-queue dequeue race.
                    h_default_sha = git
                        .fetch_ref(&def_branch_ref, "refs/ci-core/default", 64)
                        .map_err(|e| e.to_string())?;
                    git.ensure_ancestor_with_deepening(&b_sha, &h_default_sha.to_hex())
                        .map_err(|e| e.to_string())?;
                    live_tree = BareGitTree::from_commit(git.clone(), &h_default_sha)
                        .map_err(|e| e.to_string())?;
                    (live_cfg, live_onboarded) =
                        resolve_live_cfg_for_event(event, &live_tree, &target_cfg, &config_path)?;
                    if live_onboarded {
                        validate_workflows(&live_tree, &live_cfg).map_err(|e| e.to_string())?;
                        validate_codeowners(&live_tree, &live_cfg, &config_path)
                            .map_err(|e| e.to_string())?;
                    }
                    run_mg_attempt(&live_cfg, &h_default_sha)?
                }
                Err(e) => return Err(e),
            }
        }
        TriggerEvent::Push => {
            publish_eligible = true;
            let expected_ref = format!("refs/heads/{}", live_cfg.repo.default_branch);
            if runtime_ref != expected_ref {
                return Err(format!("push ref {runtime_ref:?} != {expected_ref:?}"));
            }
            validate_workflows(&event_tree, &target_cfg).map_err(|e| e.to_string())?;
            validate_codeowners(&event_tree, &target_cfg, &config_path)
                .map_err(|e| e.to_string())?;
            TcbPlan::NotRequired
        }
    };

    let plan_now = now_unix_secs();

    if let TcbPlan::Blocked { ref paths } = tcb_plan {
        let live_cp = live_cfg.control_plane();
        if !caller_allowed(&live_cp.caller, event, &observed_run)
            || verify_engine_workflows(&observed_run.referenced_workflows, &live_cp.signer, event)
                .is_err()
        {
            return Err(format!(
                "unapproved TCB PR also modified engine caller/pinning ({paths:?})"
            ));
        }
        let dummy_reg = GhcrRegistry::new(
            &live_cfg.repo.slug,
            &live_cfg.repo.effective_cas_repo(),
            &live_cfg.repo.effective_cache_repo(),
            None,
        )
        .map_err(|e| e.to_string())?;
        let dummy_val = TreeValidatedConfig::empty();
        let (blocked_plan, _) = build_plan(
            run_attempt,
            plan_now,
            event,
            shadow_mode,
            force_execute_all,
            runtime_ref,
            base_ref,
            event_sha,
            second_parent,
            false,
            base_cfg_sha256,
            candidate_cfg_sha256,
            merge_group_chain_trees,
            tcb_plan,
            &live_cp.signer,
            &live_cfg,
            &dummy_val,
            &dummy_reg,
        )?;
        write_plan_outputs(&blocked_plan, &BTreeMap::new(), out_dir, github_output)?;
        return Ok(());
    }

    let eff_cp =
        resolve_effective_control_plane(&live_cfg, &tcb_plan).map_err(|e| e.to_string())?;
    if !caller_allowed_effective(&eff_cp.caller, &tcb_plan, event, &observed_run) {
        return Err(format!(
            "unauthorized caller workflow {:?}",
            observed_run.path
        ));
    }
    verify_engine_workflows(&observed_run.referenced_workflows, &eff_cp.signer, event)
        .map_err(|e| e.to_string())?;

    validate_workflows(&event_tree, &target_cfg).map_err(|e| e.to_string())?;
    validate_codeowners(&event_tree, &target_cfg, &config_path).map_err(|e| e.to_string())?;
    evaluate_event_commit_policy(
        &git,
        &target_cfg,
        event,
        &event_sha,
        pr_parents_pair,
        mg_s_chain_commits.as_deref(),
    )?;
    let (live_co_errs, target_co_errs) = fetch_codeowners_error_pair(
        &api,
        live_onboarded.then_some((&live_cfg, &live_tree, &h_default_sha)),
        &target_cfg,
        &event_tree,
        &event_sha,
    )?;
    if !live_co_errs.is_empty() || !target_co_errs.is_empty() {
        return Err(format!(
            "GitHub CODEOWNERS errors detected: live={live_co_errs:?} target={target_co_errs:?}"
        ));
    }

    let validated_target =
        validate_config_against_tree(&target_cfg, &event_tree).map_err(|e| e.to_string())?;

    let reg = GhcrRegistry::new(
        &target_cfg.repo.slug,
        &target_cfg.repo.effective_cas_repo(),
        &target_cfg.repo.effective_cache_repo(),
        ghcr_token_from_env(),
    )
    .map_err(|e| e.to_string())?;

    let (plan, bundles) = build_plan(
        run_attempt,
        plan_now,
        event,
        shadow_mode,
        force_execute_all,
        runtime_ref,
        base_ref,
        event_sha,
        second_parent,
        publish_eligible,
        base_cfg_sha256,
        candidate_cfg_sha256,
        merge_group_chain_trees,
        tcb_plan,
        &eff_cp.signer,
        &target_cfg,
        &validated_target,
        &reg,
    )?;

    write_plan_outputs(&plan, &bundles, out_dir, github_output)
}

fn write_plan_outputs(
    plan: &ExecutionPlan,
    bundles: &BTreeMap<Sha256Digest, Vec<u8>>,
    out_dir: Option<PathBuf>,
    github_output: Option<PathBuf>,
) -> Result<(), String> {
    let plan_bytes = serde_json::to_vec_pretty(plan).map_err(|e| e.to_string())?;
    let plan_sha256 = Sha256Digest::hash_bytes(&plan_bytes);

    if let Some(dir) = out_dir {
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        fs::write(dir.join("plan.json"), &plan_bytes).map_err(|e| e.to_string())?;
        let bdir = dir.join("bundles");
        fs::create_dir_all(&bdir).map_err(|e| e.to_string())?;
        for (bsha, bbytes) in bundles {
            fs::write(bdir.join(format!("{}.json", bsha.to_hex())), bbytes)
                .map_err(|e| e.to_string())?;
        }
    }

    let img_matrix: Vec<serde_json::Value> = plan
        .pending_images
        .iter()
        .map(|p| {
            serde_json::json!({
                "recipe": p.recipe.to_hex(),
                "recipe16": p.recipe.prefix16(),
                "runner": p.runner,
                "platform": p.platform.as_str(),
            })
        })
        .collect();

    let exec_matrix: Vec<serde_json::Value> = plan
        .shards
        .iter()
        .map(|s| {
            let img_recipe16 = plan
                .images
                .get(&s.image_id)
                .map(|ip| ip.recipe().prefix16())
                .unwrap_or_default();
            serde_json::json!({
                "shard_index": s.shard_index,
                "runner": s.runner,
                "image_pending": s.image_pending,
                "recipe16": img_recipe16,
                "needs_bwrap": s.needs_bwrap,
            })
        })
        .collect();

    let mode_str = match plan.mode {
        ci_core_model::types::RunMode::Enforce => "enforce",
        ci_core_model::types::RunMode::ForceExecuteAll => "force-execute-all",
        ci_core_model::types::RunMode::ShadowPrPlanOnly => "shadow-pr",
    };

    if let Some(gh_out) = github_output {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&gh_out)
            .map_err(|e| e.to_string())?;
        writeln!(f, "plan_sha256={plan_sha256}").map_err(|e| e.to_string())?;
        writeln!(f, "plan_attempt={}", plan.plan_attempt).map_err(|e| e.to_string())?;
        writeln!(f, "mode={mode_str}").map_err(|e| e.to_string())?;
        writeln!(f, "has_images={}", !plan.pending_images.is_empty()).map_err(|e| e.to_string())?;
        writeln!(f, "has_checks={}", !plan.shards.is_empty()).map_err(|e| e.to_string())?;
        writeln!(f, "needs_publish={}", plan.needs_publish).map_err(|e| e.to_string())?;
        writeln!(
            f,
            "image_matrix={}",
            serde_json::to_string(&serde_json::json!({ "include": img_matrix }))
                .map_err(|e| e.to_string())?
        )
        .map_err(|e| e.to_string())?;
        writeln!(
            f,
            "execute_matrix={}",
            serde_json::to_string(&serde_json::json!({ "include": exec_matrix }))
                .map_err(|e| e.to_string())?
        )
        .map_err(|e| e.to_string())?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_build_image(
    config_rel: &str,
    plan_dir: &Path,
    recipe_hex: &str,
    run_attempt: u32,
    bare_git_dir: &Path,
    remote_url: Option<String>,
    out_meta_dir: &Path,
    out_blob_dir: &Path,
) -> Result<(), String> {
    let config_path = RepoRelPath::new(config_rel).map_err(|e| e.to_string())?;
    let plan_bytes = fs::read(plan_dir.join("plan.json")).map_err(|e| e.to_string())?;
    let plan_sha256 = Sha256Digest::hash_bytes(&plan_bytes);
    let plan: ExecutionPlan = serde_json::from_slice(&plan_bytes).map_err(|e| e.to_string())?;
    let target_recipe = Sha256Digest::from_hex(recipe_hex).map_err(|e| e.to_string())?;
    let pending = plan
        .pending_images
        .iter()
        .find(|p| p.recipe == target_recipe)
        .ok_or_else(|| format!("recipe `{target_recipe}` not found in plan.pending_images"))?;

    verify_host_platform(pending.platform).map_err(|e| e.to_string())?;

    let eff_remote = remote_url.or_else(default_remote_url_from_env);
    let git = HardenedBareGit::init_bare(bare_git_dir, eff_remote.clone(), gh_token_from_env())
        .map_err(|e| e.to_string())?;
    if eff_remote.is_some() {
        git.fetch_oid(&plan.event_sha, 1)
            .map_err(|e| e.to_string())?;
    }
    let tree = BareGitTree::from_commit(git, &plan.event_sha).map_err(|e| e.to_string())?;
    let (target_cfg, _) = load_cfg_from_tree(&tree, &config_path)?;
    let _ = runtime_repo_identity(&target_cfg)?;
    let validated = validate_config_against_tree(&target_cfg, &tree).map_err(|e| e.to_string())?;

    let first_img_id = pending.image_ids.first();
    let closure = validated
        .image_closures
        .get(first_img_id)
        .ok_or_else(|| "missing image context closure".to_owned())?;

    let tmp_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let ctx_dir = tmp_dir.path().join("ctx");
    materialize_work_closure(&tree, closure, &ctx_dir, &[], None).map_err(|e| e.to_string())?;

    let rt = ContainerRuntime::resolve().map_err(|e| e.to_string())?;
    let local_tag = format!("ci-core-build:{}", target_recipe.prefix16());
    let extra_ba = pending.preimage.projected_build_args();
    let build_args = rt.build_image_args(
        pending.platform.as_str(),
        &pending.preimage.source_repo_label,
        &local_tag,
        &ctx_dir.join(pending.preimage.dockerfile.as_str()),
        &extra_ba,
        &ctx_dir,
    );

    let b_out = Command::new(rt.bin())
        .args(&build_args)
        .output()
        .map_err(|e| format!("container build spawn failed: {e}"))?;
    if !b_out.status.success() {
        return Err(format!(
            "container build failed: {}",
            String::from_utf8_lossy(&b_out.stderr).trim()
        ));
    }

    let layout_dir = tmp_dir.path().join("oci-layout");
    let save_res = rt.save_oci_archive_to_dir(&local_tag, &layout_dir);
    rt.rmi_force(&local_tag);
    save_res.map_err(|e| e.to_string())?;

    // Obligation `O6`: strip `manifest.json`/`repositories`, unwrap single-entry
    // OCI Index, and verify pure OCI layout before packaging `img-blob`.
    let verified = normalize_docker_save_to_pure_oci(&layout_dir).map_err(|e| e.to_string())?;

    fs::create_dir_all(out_blob_dir).map_err(|e| e.to_string())?;
    pack_dir_to_tar_zst(&layout_dir, &out_blob_dir.join("oci-image.tar.zst"))?;

    let meta = BuiltImageMeta {
        plan_sha256,
        attempt: run_attempt,
        recipe: target_recipe,
        manifest: verified.manifest_digest,
        verified_config_digest: verified.verified_config_digest,
    };
    fs::create_dir_all(out_meta_dir).map_err(|e| e.to_string())?;
    fs::write(
        out_meta_dir.join("img-meta.json"),
        serde_json::to_vec_pretty(&meta).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

fn cmd_resolve_image_blob(
    plan_dir: &Path,
    expected_plan_sha256_hex: &str,
    img_meta_root: &Path,
    shard_index: u32,
    run_attempt: u32,
    github_output: Option<PathBuf>,
) -> Result<(), String> {
    let expected_plan_sha256 =
        Sha256Digest::from_hex(expected_plan_sha256_hex).map_err(|e| e.to_string())?;
    let plan_bytes = fs::read(plan_dir.join("plan.json")).map_err(|e| e.to_string())?;
    if Sha256Digest::hash_bytes(&plan_bytes) != expected_plan_sha256 {
        return Err("plan.json sha256 mismatch in resolve-image-blob".to_owned());
    }
    let plan: ExecutionPlan = serde_json::from_slice(&plan_bytes).map_err(|e| e.to_string())?;
    let shard = plan
        .shards
        .iter()
        .find(|s| s.shard_index == shard_index)
        .ok_or_else(|| format!("shard_index {shard_index} missing from plan"))?;
    let Some(ImagePlan::PendingBuild { recipe, .. }) = plan.images.get(&shard.image_id) else {
        return Err(format!(
            "shard {shard_index} image `{}` is not PendingBuild",
            shard.image_id
        ));
    };
    let raw_img_metas: Vec<BuiltImageMeta> =
        collect_json_files_named(img_meta_root, "img-meta.json")?;
    let winners = resolve_attempt_records(
        &raw_img_metas,
        &expected_plan_sha256,
        plan.plan_attempt,
        run_attempt,
    )
    .map_err(|e| e.to_string())?;
    let winner = winners
        .get(recipe)
        .ok_or_else(|| format!("missing winning img-meta for `{recipe}`"))?;
    let artifact_name = format!("img-blob-a{}-{}", winner.attempt, recipe.prefix16());
    if let Some(gh_out) = github_output {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(gh_out)
            .map_err(|e| e.to_string())?;
        writeln!(f, "img_blob_artifact={artifact_name}").map_err(|e| e.to_string())?;
    } else {
        println!("{artifact_name}");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_execute(
    config_rel: &str,
    plan_dir: &Path,
    expected_plan_sha256_hex: &str,
    img_meta_root: &Path,
    img_blob_dir: Option<&Path>,
    shard_index: u32,
    run_attempt: u32,
    bare_git_dir: &Path,
    remote_url: Option<String>,
    out_meta_dir: &Path,
    out_blob_dir: Option<&Path>,
    github_output: Option<PathBuf>,
) -> Result<(), String> {
    let config_path = RepoRelPath::new(config_rel).map_err(|e| e.to_string())?;
    let expected_plan_sha256 =
        Sha256Digest::from_hex(expected_plan_sha256_hex).map_err(|e| e.to_string())?;
    let plan_bytes = fs::read(plan_dir.join("plan.json")).map_err(|e| e.to_string())?;
    if Sha256Digest::hash_bytes(&plan_bytes) != expected_plan_sha256 {
        return Err("plan.json sha256 mismatch in execute".to_owned());
    }
    let plan: ExecutionPlan = serde_json::from_slice(&plan_bytes).map_err(|e| e.to_string())?;
    let shard = plan
        .shards
        .iter()
        .find(|s| s.shard_index == shard_index)
        .ok_or_else(|| format!("shard_index {shard_index} missing from plan"))?;

    let eff_remote = remote_url.or_else(default_remote_url_from_env);
    let git = HardenedBareGit::init_bare(bare_git_dir, eff_remote.clone(), gh_token_from_env())
        .map_err(|e| e.to_string())?;
    if eff_remote.is_some() {
        git.fetch_oid(&plan.event_sha, 1)
            .map_err(|e| e.to_string())?;
    }
    let tree = BareGitTree::from_commit(git, &plan.event_sha).map_err(|e| e.to_string())?;
    let (target_cfg, _) = load_cfg_from_tree(&tree, &config_path)?;
    let _ = runtime_repo_identity(&target_cfg)?;
    let validated = validate_config_against_tree(&target_cfg, &tree).map_err(|e| e.to_string())?;

    let ispec = target_cfg
        .images
        .get(&shard.image_id)
        .ok_or_else(|| format!("missing image `{}`", shard.image_id))?;
    verify_host_platform(ispec.platform).map_err(|e| e.to_string())?;

    let reg = GhcrRegistry::new(
        &target_cfg.repo.slug,
        &target_cfg.repo.effective_cas_repo(),
        &target_cfg.repo.effective_cache_repo(),
        ghcr_token_from_env(),
    )
    .map_err(|e| e.to_string())?;

    let tmp_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let oci_dir = tmp_dir.path().join("oci-image");

    let (resolved_manifest, verified_layout) = match plan.images.get(&shard.image_id) {
        Some(ImagePlan::Reused { manifest, .. }) => {
            reg.fetch_oci_image_by_digest(StoreTier::PublicCas, manifest, &oci_dir)
                .map_err(|e| format!("failed to pull reused image `{manifest}`: {e}"))?;
            let vl = verify_oci_layout(&oci_dir, manifest).map_err(|e| e.to_string())?;
            (*manifest, vl)
        }
        Some(ImagePlan::PendingBuild { recipe, .. }) => {
            let raw_img_metas: Vec<BuiltImageMeta> =
                collect_json_files_named(img_meta_root, "img-meta.json")?;
            let winners = resolve_attempt_records(
                &raw_img_metas,
                &expected_plan_sha256,
                plan.plan_attempt,
                run_attempt,
            )
            .map_err(|e| e.to_string())?;
            let img_meta = winners
                .get(recipe)
                .ok_or_else(|| format!("missing winning img-meta for `{recipe}`"))?;
            let bdir = img_blob_dir
                .ok_or_else(|| "PendingBuild shard requires --img-blob-dir".to_owned())?;
            let tar_zst = bdir.join("oci-image.tar.zst");
            unpack_tar_zst_dir(&tar_zst, &oci_dir)?;
            let _ = fs::remove_file(&tar_zst);
            let vl = verify_oci_layout(&oci_dir, &img_meta.manifest).map_err(|e| e.to_string())?;
            (img_meta.manifest, vl)
        }
        None => return Err(format!("missing ImagePlan for `{}`", shard.image_id)),
    };

    // Load into Docker using exact `sha256:<verified_config_digest>` (`O6`).
    let loaded_image_id =
        docker_load_verified_oci_layout(&oci_dir, &verified_layout).map_err(|e| e.to_string())?;
    let _ = fs::remove_dir_all(&oci_dir);

    let shard_uses_cargo_locked = shard.checks.iter().any(|cid| {
        target_cfg.check(cid).is_some_and(|cs| {
            cs.caches.iter().any(|sl| {
                target_cfg
                    .caches
                    .get(sl)
                    .is_some_and(|c| c.cargo_locked.is_some())
            })
        })
    });

    let bwrap_ctx = if shard.sandbox == SandboxMode::NestedBwrap {
        let rootfs_dir = tmp_dir.path().join("rootfs");
        export_rootfs_via_docker(&loaded_image_id, &rootfs_dir).map_err(|e| e.to_string())?;
        if !shard_uses_cargo_locked && let Ok(rt) = ContainerRuntime::resolve() {
            rt.rmi_force(&loaded_image_id);
        }
        let bwrap_bin = resolve_bwrap_binary().map_err(|e| e.to_string())?;
        Some((bwrap_bin, rootfs_dir))
    } else {
        None
    };

    let eff_signer = match &plan.tcb {
        TcbPlan::RequiresOwnerApproval {
            control_plane_transition: Some(tr),
            ..
        } => tr.candidate().signer.clone(),
        _ => target_cfg.repo.signer_policy().map_err(|e| e.to_string())?,
    };

    let stage_blobs_dir = tmp_dir.path().join("staged-blobs");
    fs::create_dir_all(&stage_blobs_dir).map_err(|e| e.to_string())?;
    let mut any_blob_staged = false;
    let mut staged_cache_keys_in_shard: BTreeSet<Sha256Digest> = BTreeSet::new();
    let mut shard_fetched_cargo_locked: BTreeMap<Sha256Digest, PathBuf> = BTreeMap::new();
    let mut shard_bundles: BTreeMap<Sha256Digest, Vec<u8>> = BTreeMap::new();
    let mut outcomes: Vec<CheckExecutionOutcome> = Vec::new();
    let mut all_passed = true;

    for cid in &shard.checks {
        let splan = plan
            .scheduled_checks
            .get(cid)
            .ok_or_else(|| format!("missing scheduled plan for `{cid}`"))?;
        let cspec = target_cfg
            .check(cid)
            .ok_or_else(|| format!("missing CheckSpec `{cid}`"))?;
        let closure = validated
            .check_closures
            .get(cid)
            .ok_or_else(|| format!("missing check closure `{cid}`"))?;

        let chk_root = tmp_dir.path().join("checks").join(cid.as_str());
        let work_dir = chk_root.join("work");
        let scratch_dir = chk_root.join("scratch");
        let outputs_dir = chk_root.join("outputs");
        fs::create_dir_all(&scratch_dir).map_err(|e| e.to_string())?;
        fs::create_dir_all(&outputs_dir).map_err(|e| e.to_string())?;
        materialize_work_closure(
            &tree,
            closure,
            &work_dir,
            &cspec.writable_dirs,
            cspec.workdir.as_ref(),
        )
        .map_err(|e| e.to_string())?;

        let mut writable_overlays = Vec::with_capacity(cspec.writable_dirs.len());
        for (wi, wrel) in cspec.writable_dirs.iter().enumerate() {
            let ov_dir = chk_root.join("overlays").join(wi.to_string());
            fs::create_dir_all(&ov_dir).map_err(|e| e.to_string())?;
            writable_overlays.push((ov_dir, wrel.clone()));
        }

        // Hydrate caches (`401`/`403`/`404`/`5xx`/revoked -> fresh empty dir).
        let exec_now = now_unix_secs();
        let mut cache_mounts = Vec::with_capacity(splan.caches.len());
        let mut hydrated_records = Vec::new();
        let mut hydrated_archives_by_slot: BTreeMap<
            CacheSlotId,
            (Sha256Digest, Option<Sha256Digest>),
        > = BTreeMap::new();

        for (slot_id, pslot) in &splan.caches {
            let ckey = pslot
                .preimage
                .finalize(Some(&resolved_manifest))
                .map_err(|e| e.to_string())?;
            let ktag = LookupTag::cache_claim(&ckey);
            let slot_dir = chk_root.join("caches").join(slot_id.as_str());
            fs::create_dir_all(&slot_dir).map_err(|e| e.to_string())?;

            let mut hydrated_arch: Option<Sha256Digest> = None;
            if let Ok(Some(raw_art)) = reg.fetch_claim_artifact(pslot.tier, &ktag)
                && let Ok(vc) = verify_offline(
                    &ktag,
                    &raw_art.claim_bytes,
                    &raw_art.bundle_bytes,
                    &eff_signer,
                    exec_now,
                )
                && let Claim::Cache {
                    key,
                    slot,
                    archive,
                    size_bytes,
                    ..
                } = vc.claim()
                && key == &ckey
                && slot == slot_id
                && *size_bytes <= pslot.max_bytes
            {
                let dl_tar = chk_root.join(format!("dl-{slot_id}.tar.zst"));
                if reg
                    .fetch_blob_verified(pslot.tier, archive, &dl_tar, pslot.max_bytes)
                    .is_ok()
                    && hydrate_cache_archive(&dl_tar, &slot_dir, pslot.max_bytes).is_ok()
                {
                    let bsha = Sha256Digest::hash_bytes(&raw_art.bundle_bytes);
                    shard_bundles.insert(bsha, raw_art.bundle_bytes);
                    hydrated_records.push(HydratedCacheRecord {
                        slot: slot_id.clone(),
                        cache_key: ckey,
                        raw_claim_bytes: raw_art.claim_bytes,
                        bundle_sha256: bsha,
                    });
                    hydrated_arch = Some(*archive);
                } else {
                    let _ = fs::remove_dir_all(&slot_dir);
                    fs::create_dir_all(&slot_dir).map_err(|e| e.to_string())?;
                }
                let _ = fs::remove_file(&dl_tar);
            }

            // Pre-sandbox `cargo_locked` fetch on cache miss ONLY (`O9`),
            // memoized per finalized `CacheKeyDigest` across checks co-located
            // in the same shard (`shard_group`).
            if hydrated_arch.is_none()
                && let Some(ref cl_cfg) = target_cfg.caches[slot_id].cargo_locked
            {
                if let Some(clean_fetched) = shard_fetched_cargo_locked.get(&ckey) {
                    copy_dir_recursive(clean_fetched, &slot_dir)?;
                } else {
                    let fetch_plan =
                        audit_cargo_locked(&tree, &cl_cfg.workspace, &cl_cfg.allowed_registries)
                            .map_err(|e| e.to_string())?;
                    let fetch_stage = chk_root.join(format!("fetch-stage-{slot_id}"));
                    let clean_fetched = tmp_dir
                        .path()
                        .join("shard-cargo-locked")
                        .join(ckey.to_hex());
                    run_cargo_locked_fetch_container(
                        &fetch_plan,
                        &cl_cfg.allowed_registries,
                        &clean_fetched,
                        &fetch_stage,
                        &loaded_image_id,
                        &verified_layout.config_env,
                    )
                    .map_err(|e| e.to_string())?;
                    let _ = fs::remove_dir_all(&fetch_stage);
                    copy_dir_recursive(&clean_fetched, &slot_dir)?;
                    shard_fetched_cargo_locked.insert(ckey, clean_fetched);
                }
            }

            hydrated_archives_by_slot.insert(slot_id.clone(), (ckey, hydrated_arch));
            cache_mounts.push((slot_dir, pslot.mount.clone()));
        }

        let merged_env = build_sandbox_env(
            &verified_layout.config_env,
            &splan.action_preimage.env,
            &splan.action_preimage.pins,
            "/scratch",
            "/tmp",
        );
        let launch_spec = SandboxLaunchSpec {
            work_dir: &work_dir,
            writable_overlays: &writable_overlays,
            scratch_dir: &scratch_dir,
            outputs_dir: &outputs_dir,
            cache_mounts: &cache_mounts,
            workdir: splan.action_preimage.workdir.as_ref(),
            command: &splan.action_preimage.command,
            merged_env: &merged_env,
        };

        let passed = match shard.sandbox {
            SandboxMode::Container => {
                run_container_sandbox(&loaded_image_id, &launch_spec).map_err(|e| e.to_string())?
            }
            SandboxMode::NestedBwrap => {
                let (bwrap_bin, rootfs_dir) = bwrap_ctx.as_ref().expect("initialized");
                run_nested_bwrap_sandbox(bwrap_bin, rootfs_dir, &launch_spec)
                    .map_err(|e| e.to_string())?
            }
        };

        let finalized_action = splan.action_preimage.finalize(&resolved_manifest);
        let mut captured_outputs = BTreeMap::new();
        let mut staged_caches = Vec::new();
        let mut check_status = if passed {
            CheckExecStatus::Passed
        } else {
            CheckExecStatus::Failed
        };

        if check_status == CheckExecStatus::Passed {
            let stage_out = if plan.publish_eligible {
                Some(stage_blobs_dir.as_path())
            } else {
                None
            };
            match capture_declared_outputs(&outputs_dir, &cspec.outputs, stage_out) {
                Ok(outs) => {
                    if plan.publish_eligible && !outs.is_empty() {
                        any_blob_staged = true;
                    }
                    captured_outputs = outs;
                }
                Err(e) => {
                    eprintln!("error: output capture failed for `{cid}`: {e}");
                    check_status = CheckExecStatus::Failed;
                }
            }
        }

        if check_status == CheckExecStatus::Passed && plan.publish_eligible {
            for (slot_id, pslot) in &splan.caches {
                let (ckey, hydrated_arch) = &hydrated_archives_by_slot[slot_id];
                let already_in_shard = staged_cache_keys_in_shard.contains(ckey);
                if !should_attempt_cache_pack(
                    plan.publish_eligible,
                    cid,
                    &pslot.cold_miss_owner,
                    hydrated_arch.as_ref(),
                    already_in_shard,
                    &shard.checks,
                ) {
                    continue;
                }
                let slot_dir = chk_root.join("caches").join(slot_id.as_str());
                let tmp_pack = chk_root.join(format!("packed-{slot_id}.tar.zst"));
                let is_cl = target_cfg.caches[slot_id].cargo_locked.is_some();
                match pack_cache_archive(&slot_dir, &tmp_pack, pslot.max_bytes, is_cl) {
                    Ok(Some((new_arch, sz))) => {
                        if hydrated_arch.as_ref() != Some(&new_arch) {
                            fs::rename(&tmp_pack, stage_blobs_dir.join(new_arch.to_hex()))
                                .map_err(|e| e.to_string())?;
                            staged_cache_keys_in_shard.insert(*ckey);
                            any_blob_staged = true;
                            staged_caches.push(StagedCacheUpdate {
                                slot: slot_id.clone(),
                                cache_key: *ckey,
                                archive_sha256: new_arch,
                                size_bytes: sz,
                            });
                        } else {
                            let _ = fs::remove_file(&tmp_pack);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        // Non-fatal warning on cache pack overflow/rejection (`§5.2`).
                        eprintln!("::warning::skipping cache `{slot_id}` publish on `{cid}`: {e}");
                        let _ = fs::remove_file(&tmp_pack);
                    }
                }
            }
        }

        if check_status != CheckExecStatus::Passed {
            all_passed = false;
        }
        outcomes.push(CheckExecutionOutcome {
            check_id: cid.clone(),
            status: check_status,
            action: finalized_action,
            outputs: captured_outputs,
            hydrated_caches: hydrated_records,
            staged_caches,
        });
        let _ = fs::remove_dir_all(&chk_root);
    }

    let shard_meta = ShardMeta {
        plan_sha256: expected_plan_sha256,
        attempt: run_attempt,
        shard_index,
        outcomes,
        bundles: shard_bundles,
    };
    fs::create_dir_all(out_meta_dir).map_err(|e| e.to_string())?;
    fs::write(
        out_meta_dir.join("shard-meta.json"),
        serde_json::to_vec_pretty(&shard_meta).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    let mut emitted_shard_blob = false;
    if all_passed
        && plan.publish_eligible
        && any_blob_staged
        && let Some(bdir) = out_blob_dir
    {
        fs::create_dir_all(bdir).map_err(|e| e.to_string())?;
        for ent_res in fs::read_dir(&stage_blobs_dir).map_err(|e| e.to_string())? {
            let ent = ent_res.map_err(|e| e.to_string())?;
            fs::rename(ent.path(), bdir.join(ent.file_name())).map_err(|e| e.to_string())?;
        }
        emitted_shard_blob = true;
    }
    if let Some(gh_out) = github_output {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(gh_out)
            .map_err(|e| e.to_string())?;
        writeln!(f, "has_shard_blob={emitted_shard_blob}").map_err(|e| e.to_string())?;
    }

    if let Ok(rt) = ContainerRuntime::resolve() {
        rt.rmi_force(&loaded_image_id);
    }

    if !all_passed {
        return Err(format!("one or more checks failed in shard {shard_index}"));
    }
    Ok(())
}

struct VerifiedGateContext {
    pass: GatePass,
    live_cfg: ChecksConfig,
    target_cfg: ChecksConfig,
    plan: ExecutionPlan,
    built_images: BTreeMap<Sha256Digest, BuiltImageMeta>,
    shard_outcomes: BTreeMap<u32, ShardMeta>,
}

#[allow(clippy::too_many_arguments)]
fn evaluate_gate_or_prepublish_common(
    stage: EvalStage,
    config_rel: &str,
    plan_dir: &Path,
    expected_plan_sha256_hex: &str,
    img_meta_root: &Path,
    shard_meta_root: &Path,
    run_id: u64,
    run_attempt: u32,
    cancelled: bool,
    event_s: &str,
    runtime_ref: &str,
    base_ref: Option<&str>,
    event_sha_s: &str,
    pr_head_sha_opt: Option<&str>,
    shadow_mode: bool,
    force_execute_all: bool,
    jobs: ObservedJobResults,
    bare_git_dir: &Path,
    remote_url: Option<String>,
) -> Result<VerifiedGateContext, String> {
    let config_path = RepoRelPath::new(config_rel).map_err(|e| e.to_string())?;
    let expected_plan_sha256 =
        Sha256Digest::from_hex(expected_plan_sha256_hex).map_err(|e| e.to_string())?;
    let plan_bytes = fs::read(plan_dir.join("plan.json")).map_err(|e| e.to_string())?;
    let plan: ExecutionPlan = serde_json::from_slice(&plan_bytes).map_err(|e| e.to_string())?;
    let plan_bundles = read_bundles_dir(&plan_dir.join("bundles"))?;

    let runtime_event = parse_trigger_event(event_s)?;
    let runtime_event_sha = GitOid::from_hex(event_sha_s).map_err(|e| e.to_string())?;
    let pr_head_sha = match pr_head_sha_opt.filter(|s| !s.is_empty()) {
        Some(s) => Some(GitOid::from_hex(s).map_err(|e| e.to_string())?),
        None => None,
    };

    let eff_remote = remote_url.or_else(default_remote_url_from_env);
    let git = HardenedBareGit::init_bare(bare_git_dir, eff_remote.clone(), gh_token_from_env())
        .map_err(|e| e.to_string())?;

    let ev_depth = if runtime_event == TriggerEvent::PullRequest {
        2
    } else {
        32
    };
    if eff_remote.is_some() {
        git.fetch_oid(&runtime_event_sha, ev_depth)
            .map_err(|e| e.to_string())?;
    }
    let target_tree =
        BareGitTree::from_commit(git.clone(), &runtime_event_sha).map_err(|e| e.to_string())?;
    let (target_cfg, target_cfg_sha256) = load_cfg_from_tree(&target_tree, &config_path)?;

    let def_branch_ref = format!("refs/heads/{}", target_cfg.repo.default_branch);
    let h_default_sha = if eff_remote.is_some() {
        git.fetch_ref(&def_branch_ref, "refs/ci-core/default", 64)
            .map_err(|e| e.to_string())?
    } else {
        git.rev_parse_oid(&def_branch_ref)
            .map_err(|e| e.to_string())?
    };
    let live_tree =
        BareGitTree::from_commit(git.clone(), &h_default_sha).map_err(|e| e.to_string())?;
    let (live_cfg, live_onboarded) =
        resolve_live_cfg_for_event(runtime_event, &live_tree, &target_cfg, &config_path)?;

    let (rt_slug, rt_id) = runtime_repo_identity(&live_cfg)?;

    let mut gate_pr_parents: Option<(GitOid, GitOid)> = None;
    let pr_base_cfg_sha256 = if runtime_event == TriggerEvent::PullRequest {
        let parents = git
            .commit_parents(&runtime_event_sha)
            .map_err(|e| e.to_string())?;
        if parents.len() != 2 {
            return Err("pull_request commit does not have 2 parents".to_owned());
        }
        gate_pr_parents = Some((parents[0], parents[1]));
        let tcb_base_sha = resolve_pr_tcb_base(
            &git,
            eff_remote.as_deref(),
            &live_cfg.repo.default_branch,
            &h_default_sha,
            base_ref,
            &runtime_event_sha,
            &parents[0],
        )?;
        let tcb_base_tree =
            BareGitTree::from_commit(git.clone(), &tcb_base_sha).map_err(|e| e.to_string())?;
        Some(
            match load_optional_cfg_from_tree(&tcb_base_tree, &config_path)? {
                Some((_, d)) => d,
                None => Sha256Digest::hash_bytes(&[]),
            },
        )
    } else {
        None
    };

    let mut gate_mg_chain: Option<Vec<GitOid>> = None;
    let landed_prefix_ok = if runtime_event == TriggerEvent::MergeGroup {
        if let Some((ref exp_base_tree, ref plan_chain)) = plan.merge_group_chain_trees {
            // Walk first-parent from `B` to `H_default` (`B` is parent of `S_1`,
            // or verified via `ensure_ancestor_with_deepening`).
            let s_commits = {
                // Find `B` (`k = plan_chain.len()` steps back from `E`).
                let mut cur = runtime_event_sha;
                for _ in 0..plan_chain.len() {
                    let ps = git.commit_parents(&cur).map_err(|e| e.to_string())?;
                    if ps.is_empty() {
                        return Err("merge_group commit chain shorter than plan".to_owned());
                    }
                    cur = ps[0];
                }
                cur
            };
            git.ensure_ancestor_with_deepening(&s_commits, &h_default_sha.to_hex())
                .map_err(|e| e.to_string())?;
            let s_chain_oids = git
                .first_parent_chain(&s_commits, &runtime_event_sha)
                .map_err(|e| e.to_string())?;
            gate_mg_chain = Some(s_chain_oids);
            let landed_base_tree = git.commit_tree_oid(&s_commits).map_err(|e| e.to_string())?;
            let m_commits = git
                .first_parent_chain(&s_commits, &h_default_sha)
                .map_err(|e| e.to_string())?;
            let mut m_trees = Vec::with_capacity(m_commits.len());
            for mc in &m_commits {
                m_trees.push(git.commit_tree_oid(mc).map_err(|e| e.to_string())?);
            }
            verify_landed_prefix(exp_base_tree, plan_chain, &landed_base_tree, &m_trees)
        } else {
            false
        }
    } else {
        true
    };

    let live_tree_ok = if live_onboarded {
        validate_workflows(&live_tree, &live_cfg)
            .and_then(|()| validate_codeowners(&live_tree, &live_cfg, &config_path))
    } else {
        Ok(())
    };
    let target_tree_ok = validate_workflows(&target_tree, &target_cfg)
        .and_then(|()| validate_codeowners(&target_tree, &target_cfg, &config_path));
    let commit_policy_ok = evaluate_event_commit_policy(
        &git,
        &target_cfg,
        runtime_event,
        &runtime_event_sha,
        gate_pr_parents,
        gate_mg_chain.as_deref(),
    );

    let api = HttpGitHubApi::new(live_cfg.repo.slug.clone(), gh_token_from_env(), None)
        .map_err(|e| e.to_string())?;
    let observed_run = api.get_run_metadata(run_id).map_err(|e| e.to_string())?;
    let (live_co_errs, target_co_errs) = fetch_codeowners_error_pair(
        &api,
        live_onboarded.then_some((&live_cfg, &live_tree, &h_default_sha)),
        &target_cfg,
        &target_tree,
        &runtime_event_sha,
    )?;

    let mut approval_reviews_by_pr = BTreeMap::new();
    if let TcbPlan::RequiresOwnerApproval {
        ref required_prs, ..
    } = plan.tcb
    {
        for (pr_num, _) in required_prs {
            let revs = api
                .list_pr_reviews_all(*pr_num)
                .map_err(|e| e.to_string())?;
            approval_reviews_by_pr.insert(*pr_num, revs);
        }
    }

    let raw_imgs: Vec<BuiltImageMeta> = collect_json_files_named(img_meta_root, "img-meta.json")?;
    let built_images = resolve_attempt_records(
        &raw_imgs,
        &expected_plan_sha256,
        plan.plan_attempt,
        run_attempt,
    )
    .map_err(|e| e.to_string())?;

    let raw_shards: Vec<ShardMeta> = collect_json_files_named(shard_meta_root, "shard-meta.json")?;
    let shard_outcomes = resolve_attempt_records(
        &raw_shards,
        &expected_plan_sha256,
        plan.plan_attempt,
        run_attempt,
    )
    .map_err(|e| e.to_string())?;

    let live_shadow_pr_authorized =
        live_tree_authorizes_shadow_pr(&live_tree, &live_cfg, live_onboarded);
    let pass = evaluate_gate(
        stage,
        cancelled,
        now_unix_secs(),
        &rt_slug,
        rt_id,
        runtime_event,
        runtime_ref,
        base_ref,
        runtime_event_sha,
        pr_head_sha,
        pr_base_cfg_sha256,
        shadow_mode,
        live_shadow_pr_authorized,
        force_execute_all,
        &live_cfg,
        &target_cfg,
        target_cfg_sha256,
        live_tree_ok,
        target_tree_ok,
        commit_policy_ok,
        &live_co_errs,
        &target_co_errs,
        landed_prefix_ok,
        &observed_run,
        jobs,
        &plan_bytes,
        expected_plan_sha256,
        &plan,
        &approval_reviews_by_pr,
        &built_images,
        &shard_outcomes,
        &plan_bundles,
    )
    .map_err(|e| e.to_string())?;

    Ok(VerifiedGateContext {
        pass,
        live_cfg,
        target_cfg,
        plan,
        built_images,
        shard_outcomes,
    })
}

#[allow(clippy::too_many_arguments)]
fn cmd_publish(
    config_rel: &str,
    plan_dir: &Path,
    expected_plan_sha256: &str,
    img_meta_root: &Path,
    shard_meta_root: &Path,
    run_id: u64,
    run_attempt: u32,
    event_s: &str,
    runtime_ref: &str,
    base_ref: Option<&str>,
    event_sha_s: &str,
    shadow_mode: bool,
    force_execute_all: bool,
    job_plan_res: &str,
    job_bi_res: &str,
    job_ex_res: &str,
    bare_git_dir: &Path,
    remote_url: Option<String>,
) -> Result<(), String> {
    let jobs = ObservedJobResults {
        plan: parse_job_result(job_plan_res)?,
        build_images: parse_job_result(job_bi_res)?,
        execute: parse_job_result(job_ex_res)?,
        publish: UpstreamJobResult::Skipped,
    };

    let VerifiedGateContext {
        pass,
        live_cfg,
        target_cfg,
        plan,
        built_images,
        shard_outcomes,
    } = evaluate_gate_or_prepublish_common(
        EvalStage::PrePublish,
        config_rel,
        plan_dir,
        expected_plan_sha256,
        img_meta_root,
        shard_meta_root,
        run_id,
        run_attempt,
        false,
        event_s,
        runtime_ref,
        base_ref,
        event_sha_s,
        None,
        shadow_mode,
        force_execute_all,
        jobs,
        bare_git_dir,
        remote_url,
    )?;

    let GatePass::ReadyToPublish { check_provenance } = pass else {
        return Err("unexpected GatePass variant for PrePublish".to_owned());
    };

    let eff_cp =
        resolve_effective_control_plane(&live_cfg, &plan.tcb).map_err(|e| e.to_string())?;
    let api = HttpGitHubApi::new(live_cfg.repo.slug.clone(), gh_token_from_env(), None)
        .map_err(|e| e.to_string())?;
    let all_artifacts = api
        .list_run_artifacts(run_id, None)
        .map_err(|e| e.to_string())?;

    let reg = GhcrRegistry::new(
        &target_cfg.repo.slug,
        &target_cfg.repo.effective_cas_repo(),
        &target_cfg.repo.effective_cache_repo(),
        ghcr_token_from_env(),
    )
    .map_err(|e| e.to_string())?;

    let tmp_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let mut staged_image_claims = Vec::new();
    let mut staged_cache_claims = Vec::new();
    let mut staged_check_claims = Vec::new();

    // 1. One `img-blob` at a time (`O(1 blob)` `$RUNNER_TEMP` disk): verify &
    // push `msha256-<M>` BEFORE minting any signature!
    for (recipe, bmeta) in &built_images {
        let art_name = format!("img-blob-a{}-{}", bmeta.attempt, recipe.prefix16());
        let art = all_artifacts
            .iter()
            .find(|a| a.name == art_name)
            .ok_or_else(|| format!("missing artifact `{art_name}`"))?;
        let zip_path = tmp_dir.path().join("cur-img.zip");
        let unzip_dir = tmp_dir.path().join("cur-img-unzip");
        let layout_dir = tmp_dir.path().join("cur-img-layout");
        api.download_artifact_zip(art.id, &zip_path)
            .map_err(|e| e.to_string())?;
        extract_zip_archive(&zip_path, &unzip_dir)?;
        let _ = fs::remove_file(&zip_path);
        unpack_tar_zst_dir(&unzip_dir.join("oci-image.tar.zst"), &layout_dir)?;
        let _ = fs::remove_dir_all(&unzip_dir);

        let anchor = LookupTag::image_manifest(&bmeta.manifest);
        let push_res = reg.push_untouched_oci_layout(
            StoreTier::PublicCas,
            &layout_dir,
            &bmeta.manifest,
            &anchor,
        );
        let _ = fs::remove_dir_all(&layout_dir);
        push_res.map_err(|e| format!("push_untouched_oci_layout `{anchor}`: {e}"))?;

        let iclaim = Claim::Image {
            recipe: *recipe,
            manifest: bmeta.manifest,
        };
        staged_image_claims.push(
            StagedClaim::new(StoreTier::PublicCas, &iclaim, Vec::new())
                .map_err(|e| e.to_string())?,
        );
    }

    // Determine lexicographically first `c_updater ∈ R_exec` per
    // `(StoreTier, CacheKeyDigest)` so each updated cache key is published once.
    let mut winning_cache_updaters: BTreeMap<
        (StoreTier, Sha256Digest),
        (CheckId, CacheSlotId, Sha256Digest, u64),
    > = BTreeMap::new();
    for smeta in shard_outcomes.values() {
        for out in &smeta.outcomes {
            for sc in &out.staged_caches {
                let tier = target_cfg.caches[&sc.slot].tier;
                let key = (tier, sc.cache_key);
                let replace = match winning_cache_updaters.get(&key) {
                    None => true,
                    Some((prev_cid, _, _, _)) => &out.check_id < prev_cid,
                };
                if replace {
                    winning_cache_updaters.insert(
                        key,
                        (
                            out.check_id.clone(),
                            sc.slot.clone(),
                            sc.archive_sha256,
                            sc.size_bytes,
                        ),
                    );
                }
            }
        }
    }

    // 2. One `shard-blob` at a time: verify & upload output/cache blobs BEFORE
    // signing!
    for (shard_idx, smeta) in &shard_outcomes {
        let mut needed_blobs: Vec<(StoreTier, Sha256Digest, u64)> = Vec::new();
        for out in &smeta.outcomes {
            for odig in out.outputs.values() {
                needed_blobs.push((StoreTier::PublicCas, odig.sha256, odig.size_bytes));
            }
            for sc in &out.staged_caches {
                let tier = target_cfg.caches[&sc.slot].tier;
                if let Some((win_cid, _, _, _)) = winning_cache_updaters.get(&(tier, sc.cache_key))
                    && win_cid == &out.check_id
                {
                    needed_blobs.push((tier, sc.archive_sha256, sc.size_bytes));
                }
            }
        }

        if !needed_blobs.is_empty() {
            let art_name = format!("shard-blob-a{}-{shard_idx}", smeta.attempt);
            let art = all_artifacts
                .iter()
                .find(|a| a.name == art_name)
                .ok_or_else(|| format!("missing artifact `{art_name}`"))?;
            let zip_path = tmp_dir.path().join("cur-shard.zip");
            let unzip_dir = tmp_dir.path().join("cur-shard-unzip");
            api.download_artifact_zip(art.id, &zip_path)
                .map_err(|e| e.to_string())?;
            extract_zip_archive(&zip_path, &unzip_dir)?;
            let _ = fs::remove_file(&zip_path);

            for (tier, bdig, bsz) in needed_blobs {
                let blob_file = unzip_dir.join(bdig.to_hex());
                if let Err(e) = reg.upload_verified_blob(tier, &blob_file, &bdig, bsz) {
                    let _ = fs::remove_dir_all(&unzip_dir);
                    return Err(format!("upload_verified_blob `{bdig}`: {e}"));
                }
            }
            let _ = fs::remove_dir_all(&unzip_dir);
        }

        for out in &smeta.outcomes {
            let prov = check_provenance
                .get(&out.check_id)
                .cloned()
                .unwrap_or_default();
            let mut payload_layers = Vec::with_capacity(out.outputs.len());
            for (oname, odig) in &out.outputs {
                payload_layers.push(BlobDescriptor {
                    digest: odig.sha256,
                    size_bytes: odig.size_bytes,
                    media_type: "application/octet-stream".to_owned(),
                    title: Some(oname.as_str().to_owned()),
                });
            }
            let cclaim = Claim::Check {
                action: out.action,
                outputs: out.outputs.clone(),
                provenance_signers: prov,
            };
            staged_check_claims.push(
                StagedClaim::new(StoreTier::PublicCas, &cclaim, payload_layers)
                    .map_err(|e| e.to_string())?,
            );
        }
    }

    for ((tier, ckey), (win_cid, slot_id, arch_sha, arch_sz)) in &winning_cache_updaters {
        let prov = check_provenance.get(win_cid).cloned().unwrap_or_default();
        let kclaim = Claim::Cache {
            key: *ckey,
            slot: slot_id.clone(),
            archive: *arch_sha,
            size_bytes: *arch_sz,
            provenance_signers: prov,
        };
        let payload = vec![BlobDescriptor {
            digest: *arch_sha,
            size_bytes: *arch_sz,
            media_type: "application/vnd.ci-core.cache.v1.tar+zstd".to_owned(),
            title: None,
        }];
        staged_cache_claims
            .push(StagedClaim::new(*tier, &kclaim, payload).map_err(|e| e.to_string())?);
    }

    let mut all_staged = Vec::new();
    all_staged.extend(staged_image_claims.iter().cloned());
    all_staged.extend(staged_cache_claims.iter().cloned());
    all_staged.extend(staged_check_claims.iter().cloned());

    if all_staged.is_empty() {
        return Ok(());
    }

    // 3. Mint ONE batch `Bundle0_3` (`0` GitHub Attestations API calls) and
    // commit Claim manifests bottom-up: `isha256` -> `ksha256` -> `asha256`.
    let raw_jwt = request_actions_oidc_jwt().map_err(|e| e.to_string())?;
    let bundle_blob = sign_batch_claims_online(&raw_jwt, &eff_cp.signer, &all_staged)
        .map_err(|e| e.to_string())?;

    commit_claims_bottom_up(
        &reg,
        &bundle_blob,
        &staged_image_claims,
        &staged_cache_claims,
        &staged_check_claims,
    )
    .map_err(|e| e.to_string())?;

    println!(
        "publish committed {} image(s), {} cache(s), and {} check receipt(s)",
        staged_image_claims.len(),
        staged_cache_claims.len(),
        staged_check_claims.len()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_gate(
    config_rel: &str,
    plan_dir: &Path,
    expected_plan_sha256: &str,
    img_meta_root: &Path,
    shard_meta_root: &Path,
    run_id: u64,
    run_attempt: u32,
    cancelled: bool,
    event_s: &str,
    runtime_ref: &str,
    base_ref: Option<&str>,
    event_sha_s: &str,
    pr_head_sha_opt: Option<&str>,
    shadow_mode: bool,
    force_execute_all: bool,
    job_plan_res: &str,
    job_bi_res: &str,
    job_ex_res: &str,
    job_pub_res: &str,
    bare_git_dir: &Path,
    remote_url: Option<String>,
) -> Result<(), String> {
    let jobs = ObservedJobResults {
        plan: parse_job_result(job_plan_res)?,
        build_images: parse_job_result(job_bi_res)?,
        execute: parse_job_result(job_ex_res)?,
        publish: parse_job_result(job_pub_res)?,
    };

    let VerifiedGateContext { pass, plan, .. } = evaluate_gate_or_prepublish_common(
        EvalStage::FinalGate,
        config_rel,
        plan_dir,
        expected_plan_sha256,
        img_meta_root,
        shard_meta_root,
        run_id,
        run_attempt,
        cancelled,
        event_s,
        runtime_ref,
        base_ref,
        event_sha_s,
        pr_head_sha_opt,
        shadow_mode,
        force_execute_all,
        jobs,
        bare_git_dir,
        remote_url,
    )?;

    println!(
        "gate accepted ({pass:?}): reused={} executed={}",
        plan.reused_checks.len(),
        plan.scheduled_checks.len()
    );
    Ok(())
}

fn find_job_by_suffix<'a>(jobs: &'a [ObservedRunJob], suffix: &str) -> Option<&'a ObservedRunJob> {
    jobs.iter()
        .find(|j| j.name == suffix || j.name.ends_with(&format!(" / {suffix}")))
}

fn conclusion_to_job_result(c: Option<&str>) -> UpstreamJobResult {
    match c {
        Some("success") => UpstreamJobResult::Success,
        Some("skipped") => UpstreamJobResult::Skipped,
        Some("cancelled") => UpstreamJobResult::Cancelled,
        _ => UpstreamJobResult::Failure,
    }
}

fn cmd_review_rerun(
    config_rel: &str,
    signal_conclusion: &str,
    head_sha_str: &str,
    bare_git_dir: &Path,
    remote_url: Option<String>,
) -> Result<(), String> {
    if signal_conclusion != "success" {
        return Ok(());
    }
    let config_path = RepoRelPath::new(config_rel).map_err(|e| e.to_string())?;
    let target_head_sha = GitOid::from_hex(head_sha_str).map_err(|e| e.to_string())?;
    let tok = gh_token_from_env().ok_or_else(|| "review-rerun requires GITHUB_TOKEN".to_owned())?;

    let eff_remote = remote_url.or_else(default_remote_url_from_env);
    let git = HardenedBareGit::init_bare(bare_git_dir, eff_remote.clone(), Some(tok.clone()))
        .map_err(|e| e.to_string())?;
    let h_def = if eff_remote.is_some() {
        git.fetch_ref("HEAD", "refs/ci-core/default", 1)
            .map_err(|e| e.to_string())?
    } else {
        git.rev_parse_oid("HEAD").map_err(|e| e.to_string())?
    };
    let live_tree = BareGitTree::from_commit(git.clone(), &h_def).map_err(|e| e.to_string())?;
    let (live_cfg, _) = load_cfg_from_tree(&live_tree, &config_path)?;
    let _ = runtime_repo_identity(&live_cfg)?;

    let client =
        GitHubRerunClient::new(live_cfg.repo.slug.clone(), tok, None).map_err(|e| e.to_string())?;
    let open_prs = client
        .list_open_prs_matching_head(&live_cfg.repo.default_branch, &target_head_sha)
        .map_err(|e| e.to_string())?;

    for pr in open_prs {
        let reviews = client
            .read_only()
            .list_pr_reviews_all(pr.number)
            .map_err(|e| e.to_string())?;
        // Obligation `O1b`: relevant-review guard recognizes DISMISSED or any
        // owner APPROVED/CHANGES_REQUESTED/`/ci-core {approve,unapprove}` review.
        if !has_relevant_review_for_stage2(&reviews, &live_cfg.tcb.owner_user_ids) {
            continue;
        }
        let approved = is_owner_approved(
            &reviews,
            &live_cfg.tcb.owner_user_ids,
            live_cfg.tcb.allow_owner_self_approval,
            &pr.head_sha,
        );

        let live_cp = live_cfg.control_plane();
        let candidate_cp = if eff_remote.is_none() || git.fetch_oid(&pr.head_sha, 1).is_ok() {
            BareGitTree::from_commit(git.clone(), &pr.head_sha)
                .ok()
                .and_then(|t| t.read_blob(&config_path).ok())
                .and_then(|b| String::from_utf8(b).ok())
                .and_then(|s| ControlPlaneHeader::parse_toml(&s).ok())
                .and_then(|h| h.control_plane().ok())
                .unwrap_or_else(|| live_cp.clone())
        } else {
            live_cp.clone()
        };

        let all_runs = client
            .list_pr_workflow_runs(&pr.head_sha)
            .map_err(|e| e.to_string())?;
        // Group matching runs by `(is_org_required_workflow, workflow_id, path)`
        // and keep the highest `run_id` (latest run) per distinct caller.
        let mut latest_by_caller: BTreeMap<
            (bool, u64, String),
            ci_core_cli::github_api::ObservedPrWorkflowRun,
        > = BTreeMap::new();
        for run in all_runs {
            let matches_live =
                caller_allowed(&live_cp.caller, TriggerEvent::PullRequest, &run.meta);
            let matches_cand =
                caller_allowed(&candidate_cp.caller, TriggerEvent::PullRequest, &run.meta);
            if !matches_live && !matches_cand {
                continue;
            }
            let key = (
                run.meta.is_org_required_workflow,
                run.meta.workflow_id,
                run.meta.path.clone(),
            );
            let replace = match latest_by_caller.get(&key) {
                None => true,
                Some(prev) => run.run_id > prev.run_id,
            };
            if replace {
                latest_by_caller.insert(key, run);
            }
        }

        for (_, mut run) in latest_by_caller {
            // Teardown / in-flight poll (`<= 660s`, Obligation `O7`).
            let poll_deadline = SystemTime::now() + Duration::from_secs(660);
            let mut jobs_list = client
                .list_attempt_jobs_all(run.run_id, run.run_attempt)
                .map_err(|e| e.to_string())?;

            let mut skip_run = false;
            while run.status != "completed" {
                let snap = InflightRunSnapshot {
                    run_status: run.status.clone(),
                    plan_status: find_job_by_suffix(&jobs_list, "plan").map(|j| j.status.clone()),
                    build_images_status: find_job_by_suffix(&jobs_list, "build-images")
                        .map(|j| j.status.clone()),
                    execute_status: find_job_by_suffix(&jobs_list, "execute")
                        .map(|j| j.status.clone()),
                };
                match classify_inflight_run_poll(&snap) {
                    InflightRunAction::Completed => break,
                    InflightRunAction::LeaveUntouched => {
                        skip_run = true;
                        break;
                    }
                    InflightRunAction::PollUntilSettled => {
                        if SystemTime::now() >= poll_deadline {
                            skip_run = true;
                            break;
                        }
                        std::thread::sleep(Duration::from_secs(10));
                        let refreshed = client
                            .list_pr_workflow_runs(&pr.head_sha)
                            .map_err(|e| e.to_string())?;
                        if let Some(updated) =
                            refreshed.into_iter().find(|r| r.run_id == run.run_id)
                        {
                            run = updated;
                            jobs_list = client
                                .list_attempt_jobs_all(run.run_id, run.run_attempt)
                                .map_err(|e| e.to_string())?;
                        } else {
                            skip_run = true;
                            break;
                        }
                    }
                }
            }
            if skip_run || run.status != "completed" {
                continue;
            }

            let completed_jobs = CompletedRunJobs {
                plan: conclusion_to_job_result(
                    find_job_by_suffix(&jobs_list, "plan").and_then(|j| j.conclusion.as_deref()),
                ),
                build_images: find_job_by_suffix(&jobs_list, "build-images")
                    .map(|j| conclusion_to_job_result(j.conclusion.as_deref()))
                    .unwrap_or(UpstreamJobResult::Skipped),
                execute: find_job_by_suffix(&jobs_list, "execute")
                    .map(|j| conclusion_to_job_result(j.conclusion.as_deref()))
                    .unwrap_or(UpstreamJobResult::Skipped),
                gate: conclusion_to_job_result(
                    find_job_by_suffix(&jobs_list, "gate").and_then(|j| j.conclusion.as_deref()),
                ),
            };

            let run_valid_live =
                caller_allowed(&live_cp.caller, TriggerEvent::PullRequest, &run.meta)
                    && verify_engine_workflows(
                        &run.meta.referenced_workflows,
                        &live_cp.signer,
                        TriggerEvent::PullRequest,
                    )
                    .is_ok();
            let run_valid_cand =
                caller_allowed(&candidate_cp.caller, TriggerEvent::PullRequest, &run.meta)
                    && verify_engine_workflows(
                        &run.meta.referenced_workflows,
                        &candidate_cp.signer,
                        TriggerEvent::PullRequest,
                    )
                    .is_ok();

            let tmp_art = tempfile::tempdir().map_err(|e| e.to_string())?;
            let plan_opt: Option<ExecutionPlan> = client
                .read_only()
                .list_run_artifacts(run.run_id, None)
                .ok()
                .and_then(|arts| {
                    let best = arts
                        .iter()
                        .filter_map(|a| {
                            let att = a.name.strip_prefix("plan-a")?.parse::<u32>().ok()?;
                            (att <= run.run_attempt).then_some((att, a.id))
                        })
                        .max_by_key(|(att, _)| *att)?;
                    let zp = tmp_art.path().join("plan.zip");
                    let uz = tmp_art.path().join("plan-uz");
                    client.read_only().download_artifact_zip(best.1, &zp).ok()?;
                    extract_zip_archive(&zp, &uz).ok()?;
                    let pb = fs::read(uz.join("plan.json")).ok()?;
                    serde_json::from_slice(&pb).ok()
                });

            let merge_ref_touches_tcb_or_pin =
                if (!approved && completed_jobs.gate == UpstreamJobResult::Success)
                    || (approved
                        && plan_opt.is_none()
                        && completed_jobs.gate == UpstreamJobResult::Failure)
                {
                    let mref = format!("refs/pull/{}/merge", pr.number);
                    let lref = format!("refs/ci-core/pr-{}-merge", pr.number);
                    let fetched = if eff_remote.is_some() {
                        git.fetch_ref(&mref, &lref, 2).ok()
                    } else {
                        git.rev_parse_oid(&mref).ok()
                    };
                    fetched.and_then(|m_oid| {
                        let ps = git.commit_parents(&m_oid).ok()?;
                        if ps.len() != 2 || ps[1] != pr.head_sha {
                            return None;
                        }
                        let tcb_base_oid = git.merge_base_with_deepening(&h_def, &m_oid).ok()?;
                        let tb = BareGitTree::from_commit(git.clone(), &tcb_base_oid).ok()?;
                        let te = BareGitTree::from_commit(git.clone(), &m_oid).ok()?;
                        let (ce, _) = load_cfg_from_tree(&te, &config_path).ok()?;
                        let cb = match load_optional_cfg_from_tree(&tb, &config_path).ok()? {
                            Some((c, _)) => c,
                            None => ce.clone(),
                        };
                        let trees: [&dyn SourceTree; 2] = [&tb, &te];
                        let maps = [
                            compute_effective_tcb(&live_cfg, &config_path, &trees, &te).ok()?,
                            compute_effective_tcb(&cb, &config_path, &trees, &te).ok()?,
                            compute_effective_tcb(&ce, &config_path, &trees, &te).ok()?,
                        ];
                        let diff = diff_trees_paths(&tb, &te).ok()?;
                        let touches = diff.iter().any(|p| {
                            classify_under_joined_tcb(&maps, p) != PathTrustClass::Untrusted
                        }) || cb.control_plane() != ce.control_plane();
                        Some(touches)
                    })
                } else {
                    None
                };

            match decide_review_rerun(
                approved,
                run_valid_live,
                run_valid_live || run_valid_cand,
                completed_jobs,
                plan_opt.as_ref(),
                merge_ref_touches_tcb_or_pin,
                now_unix_secs(),
            ) {
                ReviewRerunDecision::NoOp => {}
                ReviewRerunDecision::RerunFull => {
                    client
                        .trigger_rerun_full(run.run_id)
                        .map_err(|e| e.to_string())?;
                }
                ReviewRerunDecision::RerunFailedJobs => {
                    client
                        .trigger_rerun_failed_jobs(run.run_id)
                        .map_err(|e| e.to_string())?;
                }
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_fetch_output(
    config_rel: &str,
    rev_str: &str,
    check_str: &str,
    output_str: &str,
    dest: &Path,
    worktree: Option<PathBuf>,
    bare_git_dir: Option<PathBuf>,
    remote_url: Option<String>,
) -> Result<(), String> {
    let config_path = RepoRelPath::new(config_rel).map_err(|e| e.to_string())?;
    let check_id = CheckId::new(check_str).map_err(|e| e.to_string())?;
    let output_name = OutputName::new(output_str).map_err(|e| e.to_string())?;

    let (live_cfg, target_cfg, target_tree_box): (ChecksConfig, ChecksConfig, Box<dyn SourceTree>) =
        if let Some(wt_root) = worktree {
            let wt = LocalWorktree::new(wt_root).map_err(|e| e.to_string())?;
            let (cfg, _) = load_cfg_from_tree(&wt, &config_path)?;
            (cfg.clone(), cfg, Box::new(wt))
        } else {
            let gdir = bare_git_dir
                .unwrap_or_else(|| std::env::temp_dir().join("ci-core-fetch-output.git"));
            let eff_remote = remote_url.or_else(default_remote_url_from_env);
            let git = HardenedBareGit::init_bare(&gdir, eff_remote.clone(), gh_token_from_env())
                .map_err(|e| e.to_string())?;
            let target_oid = if let Ok(oid) = GitOid::from_hex(rev_str) {
                if eff_remote.is_some() {
                    git.fetch_oid(&oid, 1).map_err(|e| e.to_string())?;
                }
                oid
            } else {
                git.rev_parse_oid(rev_str).map_err(|e| e.to_string())?
            };
            let t_tree =
                BareGitTree::from_commit(git.clone(), &target_oid).map_err(|e| e.to_string())?;
            let (t_cfg, _) = load_cfg_from_tree(&t_tree, &config_path)?;
            let def_ref = format!("refs/heads/{}", t_cfg.repo.default_branch);
            let h_def = if eff_remote.is_some() {
                git.fetch_ref(&def_ref, "refs/ci-core/default", 1)
                    .map_err(|e| e.to_string())?
            } else {
                git.rev_parse_oid(&def_ref).map_err(|e| e.to_string())?
            };
            let l_tree = BareGitTree::from_commit(git, &h_def).map_err(|e| e.to_string())?;
            let (l_cfg, _) = load_cfg_from_tree(&l_tree, &config_path)?;
            if !t_cfg.repo.same_identity(&l_cfg.repo) {
                return Err("target_cfg [repo] identity diverged from live_cfg".to_owned());
            }
            (l_cfg, t_cfg, Box::new(t_tree))
        };

    let signer_policy = live_cfg.repo.signer_policy().map_err(|e| e.to_string())?;
    let validated = validate_config_against_tree(&target_cfg, target_tree_box.as_ref())
        .map_err(|e| e.to_string())?;
    let cspec = target_cfg
        .check(&check_id)
        .ok_or_else(|| format!("unknown check `{check_id}`"))?;
    let out_spec = cspec
        .outputs
        .get(&output_name)
        .ok_or_else(|| format!("output `{output_name}` not declared on `{check_id}`"))?;
    let recipe = validated
        .image_recipe_preimage(&target_cfg, &cspec.image)?
        .digest();

    let reg = GhcrRegistry::new(
        &live_cfg.repo.slug,
        &live_cfg.repo.effective_cas_repo(),
        &live_cfg.repo.effective_cache_repo(),
        ghcr_token_from_env(),
    )
    .map_err(|e| e.to_string())?;

    let now = now_unix_secs();
    let itag = LookupTag::image_claim(&recipe);
    let raw_img = reg
        .fetch_claim_artifact(StoreTier::PublicCas, &itag)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("image receipt `{itag}` not found in GHCR"))?;
    let vc_img = verify_offline(
        &itag,
        &raw_img.claim_bytes,
        &raw_img.bundle_bytes,
        &signer_policy,
        now,
    )
    .map_err(|e| format!("image receipt `{itag}` failed offline verification: {e}"))?;
    let Claim::Image {
        recipe: claimed_recipe,
        manifest,
    } = vc_img.claim()
    else {
        return Err("expected Claim::Image".to_owned());
    };
    if claimed_recipe != &recipe {
        return Err("image receipt recipe digest mismatch".to_owned());
    }

    let action = validated
        .action_preimage(&target_cfg, &check_id)?
        .finalize(manifest);

    let atag = LookupTag::check_claim(&action);
    let raw_chk = reg
        .fetch_claim_artifact(StoreTier::PublicCas, &atag)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("check receipt `{atag}` not found in GHCR"))?;
    let vc_chk = verify_offline(
        &atag,
        &raw_chk.claim_bytes,
        &raw_chk.bundle_bytes,
        &signer_policy,
        now,
    )
    .map_err(|e| format!("check receipt `{atag}` failed offline verification: {e}"))?;
    let Claim::Check { outputs, .. } = vc_chk.claim() else {
        return Err("expected Claim::Check".to_owned());
    };
    let odig = outputs
        .get(&output_name)
        .ok_or_else(|| format!("output `{output_name}` missing from verified receipt"))?;
    if odig.size_bytes > out_spec.max_bytes {
        return Err(format!(
            "output `{output_name}` size {} > max_bytes {}",
            odig.size_bytes, out_spec.max_bytes
        ));
    }
    reg.fetch_blob_verified(StoreTier::PublicCas, &odig.sha256, dest, out_spec.max_bytes)
        .map_err(|e| format!("failed to fetch verified output blob: {e}"))?;

    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LocalCachedImageMeta {
    manifest_digest: Sha256Digest,
    verified_config_digest: Sha256Digest,
    config_env: Vec<String>,
}

fn local_cache_root() -> PathBuf {
    if let Ok(explicit) = std::env::var("CI_CORE_LOCAL_CACHE_DIR")
        && !explicit.trim().is_empty()
    {
        return PathBuf::from(explicit);
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME")
        && !xdg.trim().is_empty()
    {
        return PathBuf::from(xdg).join("ci-core");
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.trim().is_empty()
    {
        return PathBuf::from(home).join(".cache").join("ci-core");
    }
    std::env::temp_dir().join("ci-core-local-cache")
}

fn docker_image_exists(image_id: &str) -> bool {
    ContainerRuntime::resolve()
        .ok()
        .is_some_and(|rt| rt.image_exists(image_id))
}

fn cmd_run_local(
    config_rel: &str,
    check_str: &str,
    repo_root: &Path,
    native: bool,
    cold: bool,
    out_dir_opt: Option<PathBuf>,
) -> Result<(), String> {
    let config_path = RepoRelPath::new(config_rel).map_err(|e| e.to_string())?;
    let check_id = CheckId::new(check_str).map_err(|e| e.to_string())?;
    let tree = LocalWorktree::new(repo_root).map_err(|e| e.to_string())?;
    let (cfg, _) = load_cfg_from_tree(&tree, &config_path)?;
    // Note (§5.3): `run-local` enforces `validate_config_against_tree` (Cargo +
    // `tree::validate_source_closure`) while keeping `validate_workflows` /
    // `validate_codeowners` inside `verify-repo` so developers can run checks
    // mid-edit on workflows.
    let validated = validate_config_against_tree(&cfg, &tree).map_err(|e| e.to_string())?;
    let cspec = cfg
        .check(&check_id)
        .ok_or_else(|| format!("unknown check `{check_id}`"))?;
    let ispec = cfg
        .images
        .get(&cspec.image)
        .ok_or_else(|| format!("missing image `{}`", cspec.image))?;

    let run_mode = if native {
        LocalRunMode::NativeUnsandboxed
    } else {
        verify_host_platform(ispec.platform).map_err(|e| e.to_string())?;
        LocalRunMode::Sandboxed(cspec.sandbox)
    };

    let reg = GhcrRegistry::new(
        &cfg.repo.slug,
        &cfg.repo.effective_cas_repo(),
        &cfg.repo.effective_cache_repo(),
        ghcr_token_from_env(),
    )
    .map_err(|e| e.to_string())?;
    let signer_policy = cfg.repo.signer_policy().map_err(|e| e.to_string())?;
    let now = now_unix_secs();
    let host_cache = (!cold).then(local_cache_root);

    let tmp_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let work_dir = tmp_dir.path().join("work");
    let scratch_dir = tmp_dir.path().join("scratch");
    let outputs_dir = tmp_dir.path().join("outputs");
    fs::create_dir_all(&scratch_dir).map_err(|e| e.to_string())?;
    fs::create_dir_all(&outputs_dir).map_err(|e| e.to_string())?;

    materialize_work_closure(
        &tree,
        &validated.check_closures[&check_id],
        &work_dir,
        &cspec.writable_dirs,
        cspec.workdir.as_ref(),
    )
    .map_err(|e| e.to_string())?;

    let mut writable_overlays = Vec::new();
    for (wi, wrel) in cspec.writable_dirs.iter().enumerate() {
        let ov = tmp_dir.path().join("overlays").join(wi.to_string());
        fs::create_dir_all(&ov).map_err(|e| e.to_string())?;
        writable_overlays.push((ov, wrel.clone()));
    }

    let mut oci_env: Vec<String> = Vec::new();
    let mut loaded_image_id = String::new();
    let mut resolved_manifest_opt: Option<Sha256Digest> = None;
    let mut verified_cfg_digest_opt: Option<Sha256Digest> = None;

    if let LocalRunMode::Sandboxed(_) = run_mode {
        let recipe_pre = validated.image_recipe_preimage(&cfg, &cspec.image)?;
        let recipe = recipe_pre.digest();

        let oci_dir = tmp_dir.path().join("oci-layout");
        let itag = LookupTag::image_claim(&recipe);
        let mut resolved_local_img = false;

        // 1. Check warm local Docker + recipe cache first when `!cold`.
        if !cold && let Some(ref croot) = host_cache {
            let meta_file = croot
                .join("images")
                .join(format!("{}.json", recipe.to_hex()));
            if let Ok(bytes) = fs::read(&meta_file)
                && let Ok(cached_meta) = serde_json::from_slice::<LocalCachedImageMeta>(&bytes)
            {
                let cand_id = cached_meta.verified_config_digest.to_oci_digest();
                if docker_image_exists(&cand_id) {
                    oci_env = cached_meta.config_env;
                    loaded_image_id = cand_id;
                    resolved_manifest_opt = Some(cached_meta.manifest_digest);
                    verified_cfg_digest_opt = Some(cached_meta.verified_config_digest);
                    resolved_local_img = true;
                }
            }
        }

        // 2. Otherwise probe attested GHCR image receipt when `!cold`.
        if !resolved_local_img
            && !cold
            && let Ok(Some(raw_img)) = reg.fetch_claim_artifact(StoreTier::PublicCas, &itag)
            && let Ok(vc) = verify_offline(
                &itag,
                &raw_img.claim_bytes,
                &raw_img.bundle_bytes,
                &signer_policy,
                now,
            )
            && let Claim::Image {
                recipe: claimed_recipe,
                manifest,
            } = vc.claim()
            && claimed_recipe == &recipe
            && reg
                .fetch_oci_image_by_digest(StoreTier::PublicCas, manifest, &oci_dir)
                .is_ok()
        {
            let vl = verify_oci_layout(&oci_dir, manifest).map_err(|e| e.to_string())?;
            loaded_image_id =
                docker_load_verified_oci_layout(&oci_dir, &vl).map_err(|e| e.to_string())?;
            let _ = fs::remove_dir_all(&oci_dir);
            if let Some(ref croot) = host_cache {
                let imgs_dir = croot.join("images");
                let _ = fs::create_dir_all(&imgs_dir);
                let meta = LocalCachedImageMeta {
                    manifest_digest: *manifest,
                    verified_config_digest: vl.verified_config_digest,
                    config_env: vl.config_env.clone(),
                };
                if let Ok(jb) = serde_json::to_vec_pretty(&meta) {
                    let _ = fs::write(imgs_dir.join(format!("{}.json", recipe.to_hex())), jb);
                }
            }
            oci_env = vl.config_env;
            resolved_manifest_opt = Some(*manifest);
            verified_cfg_digest_opt = Some(vl.verified_config_digest);
            resolved_local_img = true;
        }

        // 3. Build locally from isolated `image_closures` context on miss / `--cold`.
        if !resolved_local_img {
            let rt = ContainerRuntime::resolve().map_err(|e| e.to_string())?;
            let ctx_dir = tmp_dir.path().join("img-ctx");
            materialize_work_closure(
                &tree,
                &validated.image_closures[&cspec.image],
                &ctx_dir,
                &[],
                None,
            )
            .map_err(|e| e.to_string())?;
            let ltag = format!("ci-core-local:{}", recipe.prefix16());
            let extra_ba = recipe_pre.projected_build_args();
            let bargs = rt.build_image_args(
                recipe_pre.platform.as_str(),
                &recipe_pre.source_repo_label,
                &ltag,
                &ctx_dir.join(recipe_pre.dockerfile.as_str()),
                &extra_ba,
                &ctx_dir,
            );
            let st = Command::new(rt.bin()).args(&bargs).status().map_err(|e| {
                format!("container build failed (pass `--native` on containerless hosts): {e}")
            })?;
            if !st.success() {
                return Err("local container build failed".to_owned());
            }
            let (cfg_digest, inspected_env) =
                rt.inspect_local_image(&ltag).map_err(|e| e.to_string())?;
            loaded_image_id = cfg_digest.to_oci_digest();
            if let Some(ref croot) = host_cache {
                let imgs_dir = croot.join("images");
                let _ = fs::create_dir_all(&imgs_dir);
                let meta = LocalCachedImageMeta {
                    manifest_digest: cfg_digest,
                    verified_config_digest: cfg_digest,
                    config_env: inspected_env.clone(),
                };
                if let Ok(jb) = serde_json::to_vec_pretty(&meta) {
                    let _ = fs::write(imgs_dir.join(format!("{}.json", recipe.to_hex())), jb);
                }
            }
            oci_env = inspected_env;
            resolved_manifest_opt = Some(cfg_digest);
            verified_cfg_digest_opt = Some(cfg_digest);
        }
    }

    let mut cache_mounts = Vec::new();
    let mut local_slot_keys: Vec<(CacheSlotId, PathBuf, Option<Sha256Digest>)> = Vec::new();
    for slot_id in &cspec.caches {
        let slot_spec = &cfg.caches[slot_id];
        let slot_dir = tmp_dir.path().join("caches").join(slot_id.as_str());
        fs::create_dir_all(&slot_dir).map_err(|e| e.to_string())?;

        let mut hydrated = false;
        let cpre = validated.cache_key_preimage(&cfg, &check_id, slot_id)?;
        let ckey_opt = cpre.finalize(resolved_manifest_opt.as_ref()).ok();

        if !cold && let Some(ckey) = ckey_opt {
            if let Some(ref croot) = host_cache {
                let local_tar = croot
                    .join("slots")
                    .join(format!("{}.tar.zst", ckey.to_hex()));
                if local_tar.is_file() {
                    if hydrate_cache_archive(&local_tar, &slot_dir, slot_spec.max_bytes).is_ok() {
                        hydrated = true;
                    } else {
                        let _ = fs::remove_dir_all(&slot_dir);
                        fs::create_dir_all(&slot_dir).map_err(|e| e.to_string())?;
                    }
                }
            }
            if !hydrated {
                let ktag = LookupTag::cache_claim(&ckey);
                if let Ok(Some(raw_art)) = reg.fetch_claim_artifact(slot_spec.tier, &ktag)
                    && let Ok(vc) = verify_offline(
                        &ktag,
                        &raw_art.claim_bytes,
                        &raw_art.bundle_bytes,
                        &signer_policy,
                        now,
                    )
                    && let Claim::Cache {
                        key,
                        slot,
                        archive,
                        size_bytes,
                        ..
                    } = vc.claim()
                    && key == &ckey
                    && slot == slot_id
                    && *size_bytes <= slot_spec.max_bytes
                {
                    let dl = tmp_dir.path().join(format!("dl-{slot_id}.tar.zst"));
                    if reg
                        .fetch_blob_verified(slot_spec.tier, archive, &dl, slot_spec.max_bytes)
                        .is_ok()
                        && hydrate_cache_archive(&dl, &slot_dir, slot_spec.max_bytes).is_ok()
                    {
                        hydrated = true;
                    } else {
                        let _ = fs::remove_dir_all(&slot_dir);
                        fs::create_dir_all(&slot_dir).map_err(|e| e.to_string())?;
                    }
                    let _ = fs::remove_file(&dl);
                }
            }
        }

        if !hydrated && let Some(ref cl_cfg) = slot_spec.cargo_locked {
            let fetch_plan =
                audit_cargo_locked(&tree, &cl_cfg.workspace, &cl_cfg.allowed_registries)
                    .map_err(|e| e.to_string())?;
            let fstage = tmp_dir.path().join(format!("fetch-{slot_id}"));
            match run_mode {
                LocalRunMode::NativeUnsandboxed => {
                    run_cargo_locked_fetch_native(
                        &fetch_plan,
                        &cl_cfg.allowed_registries,
                        &slot_dir,
                        &fstage,
                        &[],
                    )
                    .map_err(|e| e.to_string())?;
                }
                LocalRunMode::Sandboxed(_) => {
                    run_cargo_locked_fetch_container(
                        &fetch_plan,
                        &cl_cfg.allowed_registries,
                        &slot_dir,
                        &fstage,
                        &loaded_image_id,
                        &oci_env,
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
        }
        local_slot_keys.push((slot_id.clone(), slot_dir.clone(), ckey_opt));
        cache_mounts.push((slot_dir, slot_spec.mount.clone()));
    }

    let apre = validated.action_preimage(&cfg, &check_id)?;
    let merged_env = build_sandbox_env(&oci_env, &apre.env, &apre.pins, "/scratch", "/tmp");
    let launch_spec = SandboxLaunchSpec {
        work_dir: &work_dir,
        writable_overlays: &writable_overlays,
        scratch_dir: &scratch_dir,
        outputs_dir: &outputs_dir,
        cache_mounts: &cache_mounts,
        workdir: apre.workdir.as_ref(),
        command: &apre.command,
        merged_env: &merged_env,
    };

    let passed = match run_mode {
        LocalRunMode::Sandboxed(SandboxMode::Container) => {
            run_container_sandbox(&loaded_image_id, &launch_spec).map_err(|e| e.to_string())?
        }
        LocalRunMode::Sandboxed(SandboxMode::NestedBwrap) => {
            let bwrap_bin = resolve_bwrap_binary().map_err(|e| e.to_string())?;
            let rootfs_dir = match (&host_cache, verified_cfg_digest_opt) {
                (Some(croot), Some(vcfg)) => {
                    let base = croot.join("rootfs").join(vcfg.to_hex());
                    let ready = base.join(".complete");
                    let target_root = base.join("root");
                    if !ready.is_file() {
                        let parent = croot.join("rootfs");
                        let _ = fs::create_dir_all(&parent);
                        let stage_base = parent.join(format!(
                            ".stage-{}-{}",
                            vcfg.prefix16(),
                            std::process::id()
                        ));
                        let _ = fs::remove_dir_all(&stage_base);
                        let stage_root = stage_base.join("root");
                        export_rootfs_via_docker(&loaded_image_id, &stage_root)
                            .map_err(|e| e.to_string())?;
                        let _ = fs::write(stage_base.join(".complete"), b"ok\n");
                        if fs::rename(&stage_base, &base).is_err() {
                            let _ = fs::remove_dir_all(&stage_base);
                        }
                    }
                    if ready.is_file() {
                        target_root
                    } else {
                        let fallback = tmp_dir.path().join("rootfs");
                        export_rootfs_via_docker(&loaded_image_id, &fallback)
                            .map_err(|e| e.to_string())?;
                        fallback
                    }
                }
                _ => {
                    let fallback = tmp_dir.path().join("rootfs");
                    export_rootfs_via_docker(&loaded_image_id, &fallback)
                        .map_err(|e| e.to_string())?;
                    fallback
                }
            };
            run_nested_bwrap_sandbox(&bwrap_bin, &rootfs_dir, &launch_spec)
                .map_err(|e| e.to_string())?
        }
        LocalRunMode::NativeUnsandboxed => {
            run_native_unsandboxed(&launch_spec).map_err(|e| e.to_string())?
        }
    };

    if !passed {
        return Err(format!("check `{check_id}` failed"));
    }

    if let Some(ref croot) = host_cache {
        let slots_dir = croot.join("slots");
        let _ = fs::create_dir_all(&slots_dir);
        for (slot_id, slot_dir, ckey_opt) in &local_slot_keys {
            let Some(ckey) = ckey_opt else { continue };
            let slot_spec = &cfg.caches[slot_id];
            let stage_tar = slots_dir.join(format!(
                ".stage-{}-{}.tar.zst",
                ckey.prefix16(),
                std::process::id()
            ));
            let is_cl = slot_spec.cargo_locked.is_some();
            if let Ok(Some(_)) =
                pack_cache_archive(slot_dir, &stage_tar, slot_spec.max_bytes, is_cl)
            {
                let final_tar = slots_dir.join(format!("{}.tar.zst", ckey.to_hex()));
                if fs::rename(&stage_tar, &final_tar).is_err() {
                    let _ = fs::remove_file(&stage_tar);
                }
            } else {
                let _ = fs::remove_file(&stage_tar);
            }
        }
    }

    let captured =
        capture_declared_outputs(&outputs_dir, &cspec.outputs, None).map_err(|e| e.to_string())?;
    if let Some(dest_out) = out_dir_opt {
        fs::create_dir_all(&dest_out).map_err(|e| e.to_string())?;
        for oname in captured.keys() {
            fs::copy(
                outputs_dir.join(oname.as_str()),
                dest_out.join(oname.as_str()),
            )
            .map_err(|e| e.to_string())?;
        }
    }
    println!("run-local `{check_id}` passed (outputs={})", captured.len());
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let res = match cli.command {
        Commands::VerifyRepo {
            config,
            repo_root,
            bare_git,
            rev,
        } => cmd_verify_repo(&config, repo_root, bare_git, rev),
        Commands::Plan {
            config,
            gc_keep,
            shadow_mode,
            force_execute_all,
            event,
            runtime_ref,
            base_ref,
            event_sha,
            pr_number,
            pr_head_sha,
            merge_group_base_sha,
            run_id,
            run_attempt,
            bare_git_dir,
            remote_url,
            out_dir,
            github_output,
        } => cmd_plan(
            &config,
            gc_keep,
            shadow_mode,
            force_execute_all,
            event,
            runtime_ref,
            base_ref,
            event_sha,
            pr_number,
            pr_head_sha,
            merge_group_base_sha,
            run_id,
            run_attempt,
            bare_git_dir,
            remote_url,
            out_dir,
            github_output,
        ),
        Commands::BuildImage {
            config,
            plan_dir,
            recipe,
            run_attempt,
            bare_git_dir,
            remote_url,
            out_meta_dir,
            out_blob_dir,
        } => cmd_build_image(
            &config,
            &plan_dir,
            &recipe,
            run_attempt,
            &bare_git_dir,
            remote_url,
            &out_meta_dir,
            &out_blob_dir,
        ),
        Commands::ResolveImageBlob {
            plan_dir,
            expected_plan_sha256,
            img_meta_root,
            shard_index,
            run_attempt,
            github_output,
        } => cmd_resolve_image_blob(
            &plan_dir,
            &expected_plan_sha256,
            &img_meta_root,
            shard_index,
            run_attempt,
            github_output,
        ),
        Commands::Execute {
            config,
            plan_dir,
            expected_plan_sha256,
            img_meta_root,
            img_blob_dir,
            shard_index,
            run_attempt,
            bare_git_dir,
            remote_url,
            out_meta_dir,
            out_blob_dir,
            github_output,
        } => cmd_execute(
            &config,
            &plan_dir,
            &expected_plan_sha256,
            &img_meta_root,
            img_blob_dir.as_deref(),
            shard_index,
            run_attempt,
            &bare_git_dir,
            remote_url,
            &out_meta_dir,
            out_blob_dir.as_deref(),
            github_output,
        ),
        Commands::Publish {
            config,
            plan_dir,
            expected_plan_sha256,
            img_meta_root,
            shard_meta_root,
            run_id,
            run_attempt,
            event,
            runtime_ref,
            base_ref,
            event_sha,
            shadow_mode,
            force_execute_all,
            job_plan_result,
            job_build_images_result,
            job_execute_result,
            bare_git_dir,
            remote_url,
        } => cmd_publish(
            &config,
            &plan_dir,
            &expected_plan_sha256,
            &img_meta_root,
            &shard_meta_root,
            run_id,
            run_attempt,
            &event,
            &runtime_ref,
            base_ref.as_deref(),
            &event_sha,
            shadow_mode,
            force_execute_all,
            &job_plan_result,
            &job_build_images_result,
            &job_execute_result,
            &bare_git_dir,
            remote_url,
        ),
        Commands::Gate {
            config,
            plan_dir,
            expected_plan_sha256,
            img_meta_root,
            shard_meta_root,
            run_id,
            run_attempt,
            cancelled,
            event,
            runtime_ref,
            base_ref,
            event_sha,
            pr_head_sha,
            shadow_mode,
            force_execute_all,
            job_plan_result,
            job_build_images_result,
            job_execute_result,
            job_publish_result,
            bare_git_dir,
            remote_url,
        } => cmd_gate(
            &config,
            &plan_dir,
            &expected_plan_sha256,
            &img_meta_root,
            &shard_meta_root,
            run_id,
            run_attempt,
            cancelled,
            &event,
            &runtime_ref,
            base_ref.as_deref(),
            &event_sha,
            pr_head_sha.as_deref(),
            shadow_mode,
            force_execute_all,
            &job_plan_result,
            &job_build_images_result,
            &job_execute_result,
            &job_publish_result,
            &bare_git_dir,
            remote_url,
        ),
        Commands::ReviewRerun {
            config,
            signal_conclusion,
            head_sha,
            bare_git_dir,
            remote_url,
        } => cmd_review_rerun(
            &config,
            &signal_conclusion,
            &head_sha,
            &bare_git_dir,
            remote_url,
        ),
        Commands::FetchOutput {
            config,
            rev,
            check,
            output,
            dest,
            worktree,
            bare_git_dir,
            remote_url,
        } => cmd_fetch_output(
            &config,
            &rev,
            &check,
            &output,
            &dest,
            worktree,
            bare_git_dir,
            remote_url,
        ),
        Commands::RunLocal {
            config,
            check,
            repo_root,
            native,
            cold,
            out_dir,
        } => cmd_run_local(&config, &check, &repo_root, native, cold, out_dir),
    };

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ci-core error: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod cli_flag_sync_tests {
    use super::*;

    #[test]
    fn workflow_cli_invocations_parse_cleanly() {
        let base_gate = [
            "ci-core",
            "gate",
            "--config",
            "ci/checks.toml",
            "--plan-dir",
            "/tmp/plan-a1",
            "--expected-plan-sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--img-meta-root",
            "/tmp/img-meta",
            "--shard-meta-root",
            "/tmp/shard-meta",
            "--run-id",
            "1",
            "--run-attempt",
            "1",
            "--event",
            "pull_request",
            "--runtime-ref",
            "refs/pull/1/merge",
            "--event-sha",
            "0000000000000000000000000000000000000000",
            "--job-plan-result",
            "success",
            "--job-build-images-result",
            "skipped",
            "--job-execute-result",
            "skipped",
            "--job-publish-result",
            "skipped",
            "--bare-git-dir",
            "/tmp/bare.git",
            "--shadow-mode",
            "--base-ref",
            "main",
            "--pr-head-sha",
            "0000000000000000000000000000000000000000",
        ];
        let parsed = Cli::try_parse_from(base_gate).expect("default gate invocation must parse");
        match parsed.command {
            Commands::Gate {
                cancelled,
                shadow_mode,
                ..
            } => {
                assert!(!cancelled);
                assert!(shadow_mode);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        // Also accept explicit `--cancelled`, `--cancelled true`, and `--cancelled false`.
        for extra in [
            vec!["--cancelled"],
            vec!["--cancelled", "true"],
            vec!["--cancelled", "false"],
        ] {
            let mut args: Vec<&str> = base_gate.to_vec();
            args.extend(extra.iter().copied());
            let p = Cli::try_parse_from(&args).expect("cancelled variants must parse");
            if let Commands::Gate { cancelled, .. } = p.command {
                assert_eq!(cancelled, extra != vec!["--cancelled", "false"]);
            } else {
                panic!("expected Gate");
            }
        }
    }
}

#[cfg(test)]
mod merge_group_base_tests {
    use super::*;
    use std::path::Path;
    use std::process::Command;

    fn git(cwd: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    fn commit(repo: &Path, name: &str) -> GitOid {
        std::fs::write(repo.join(name), name).unwrap();
        git(repo, &["add", name]);
        git(repo, &["commit", "-q", "-m", name]);
        GitOid::from_hex(&git(repo, &["rev-parse", "HEAD"])).unwrap()
    }

    struct Fixture {
        _td: tempfile::TempDir,
        bare: HardenedBareGit,
        landed: GitOid,
        head: GitOid,
        queued_1: GitOid,
        queued_2: GitOid,
        diverged: GitOid,
        side_merge: GitOid,
    }

    // main:   root - landed - head
    // queue:                  head - queued_1 - queued_2
    // other:  root - diverged
    // merge:  diverged + head (first parent `diverged`) = side_merge
    fn fixture() -> Fixture {
        let td = tempfile::tempdir().unwrap();
        let repo = td.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        let root = commit(&repo, "root");
        let landed = commit(&repo, "landed");
        let head = commit(&repo, "head");
        let queued_1 = commit(&repo, "queued-1");
        let queued_2 = commit(&repo, "queued-2");
        git(&repo, &["checkout", "-q", "-b", "other", &root.to_hex()]);
        let diverged = commit(&repo, "diverged");
        git(&repo, &["merge", "-q", "--no-edit", &head.to_hex()]);
        let side_merge = GitOid::from_hex(&git(&repo, &["rev-parse", "HEAD"])).unwrap();
        let bare = HardenedBareGit::open_existing(repo.join(".git")).unwrap();
        Fixture {
            _td: td,
            bare,
            landed,
            head,
            queued_1,
            queued_2,
            diverged,
            side_merge,
        }
    }

    #[test]
    fn head_of_queue_parent_is_default_branch() {
        let f = fixture();
        assert_eq!(
            resolve_merge_group_base(&f.bare, &f.head, &f.head).unwrap(),
            f.head
        );
    }

    #[test]
    fn landed_parent_is_kept() {
        let f = fixture();
        assert_eq!(
            resolve_merge_group_base(&f.bare, &f.landed, &f.head).unwrap(),
            f.landed
        );
    }

    #[test]
    fn queued_parent_rebases_onto_default_branch() {
        let f = fixture();
        assert_eq!(
            resolve_merge_group_base(&f.bare, &f.queued_1, &f.head).unwrap(),
            f.head
        );
        assert_eq!(
            resolve_merge_group_base(&f.bare, &f.queued_2, &f.head).unwrap(),
            f.head
        );
    }

    #[test]
    fn unrelated_parent_fails_closed() {
        let f = fixture();
        let err = resolve_merge_group_base(&f.bare, &f.diverged, &f.head).unwrap_err();
        assert!(err.contains("unrelated"), "{err}");
    }

    fn local_history_len(git_dir: &Path, tip: &GitOid) -> usize {
        let out = git(
            git_dir,
            &["--git-dir", ".", "rev-list", "--count", &tip.to_hex()],
        );
        out.parse().unwrap()
    }

    // A queued entry must resolve from shallow fetches without deepening
    // the default branch's history, and a landed parent must still resolve
    // by deepening until its ancestry is visible.
    #[test]
    fn shallow_remote_resolution_deepens_only_as_needed() {
        let td = tempfile::tempdir().unwrap();
        let repo = td.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        for i in 0..60 {
            commit(&repo, &format!("history-{i}"));
        }
        let landed = commit(&repo, "landed");
        for i in 0..40 {
            commit(&repo, &format!("after-landed-{i}"));
        }
        let head = commit(&repo, "head");
        let _queued_1 = commit(&repo, "queued-1");
        let queued_2 = commit(&repo, "queued-2");
        let remote = format!("file://{}", repo.display());

        let queued_dir = td.path().join("queued.git");
        let bare = HardenedBareGit::init_bare(&queued_dir, Some(remote.clone()), None).unwrap();
        bare.fetch_oid(&queued_2, 3).unwrap();
        bare.fetch_oid(&head, 1).unwrap();
        assert_eq!(
            resolve_merge_group_base(&bare, &queued_2, &head).unwrap(),
            head
        );
        assert_eq!(
            local_history_len(&queued_dir, &queued_2),
            3,
            "must not deepen history"
        );

        let landed_dir = td.path().join("landed.git");
        let bare = HardenedBareGit::init_bare(&landed_dir, Some(remote), None).unwrap();
        bare.fetch_oid(&landed, 1).unwrap();
        bare.fetch_oid(&head, 1).unwrap();
        assert_eq!(
            resolve_merge_group_base(&bare, &landed, &head).unwrap(),
            landed
        );
    }

    #[test]
    fn default_branch_off_first_parent_chain_fails_closed() {
        let f = fixture();
        let err = resolve_merge_group_base(&f.bare, &f.side_merge, &f.head).unwrap_err();
        assert!(err.contains("first-parent chain"), "{err}");
    }
}
