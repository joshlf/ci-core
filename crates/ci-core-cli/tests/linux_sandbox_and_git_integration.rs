//! Live Linux kernel sandbox (`NestedBwrap`), bare-Git `.gitattributes` RCE
//! neutralization + `mergeQueue` replay (`MERGE`, `SQUASH`, `REBASE`), `O6`
//! pure OCI layout verification, `O_NOFOLLOW` output/cache hardlink & symlink
//! confinement, `O9` isolated-`cwd` `cargo fetch --locked` (`RUSTUP_HOME`
//! preserved), and end-to-end `InMemoryRegistry` `m->i->k->a` pipeline tests.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use ci_core_cli::ghcr::{InMemoryRegistry, normalize_docker_save_to_pure_oci, verify_oci_layout};
use ci_core_cli::git_bare::{BareGitSliceReplayer, HardenedBareGit, LocalWorktree};
use ci_core_cli::sandbox::{
    ContainerRuntime, SandboxLaunchSpec, build_sandbox_env, capture_declared_outputs,
    extract_tar_stripping_special, hydrate_cache_archive, pack_cache_archive, resolve_bwrap_binary,
    run_cargo_locked_fetch_native, run_nested_bwrap_sandbox, verify_bwrap_userns_preflight,
    write_docker_load_tar,
};
use ci_core_cli::signer::{StagedClaim, commit_claims_bottom_up, validate_actions_oidc_jwt_claims};
use ci_core_model::cargo_static::audit_cargo_locked;
use ci_core_model::config::DeclaredOutputSpec;
use ci_core_model::store::{
    BlobDescriptor, BlobRef, MergeMethod, MergeQueueEntry, MergeQueueEntryState, Registry,
    StoreTier,
};
use ci_core_model::tcb::CommitSliceReplayer;
use ci_core_model::types::{
    AbsUnixPath, CacheSlotId, Claim, GitOid, LookupTag, NonEmptyVec, OutputDigest, OutputName,
    PinId, PinKey, RegistryIndexUrl, RepoRelPath, Sha256Digest, SignerPolicy, SigstoreRoot,
    WorkflowUri,
};

fn git_cmd(cwd: &Path, args: &[&str]) -> String {
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

// ---------------------------------------------------------------------------
// 1. Bare-Git `.gitattributes` RCE Neutralization & MergeQueue Replay
// ---------------------------------------------------------------------------

#[test]
fn bare_git_merge_tree_neutralizes_gitattributes_driver_rce_and_replays_slices() {
    let td = tempfile::tempdir().unwrap();
    let sentinel = td.path().join("PWNED_BY_MERGE_DRIVER");
    let src_repo = td.path().join("src-repo");
    fs::create_dir_all(&src_repo).unwrap();

    git_cmd(&src_repo, &["init", "-b", "main"]);
    // Configure a malicious merge driver in `src_repo` AND `.gitattributes` so a non-bare
    // worktree merge would execute `touch <sentinel>`!
    git_cmd(
        &src_repo,
        &[
            "config",
            "merge.evil.driver",
            &format!("touch {} && exit 0", sentinel.display()),
        ],
    );
    fs::write(src_repo.join(".gitattributes"), "*.txt merge=evil\n").unwrap();
    fs::write(src_repo.join("file.txt"), "line1\nline2\nline3\n").unwrap();
    git_cmd(&src_repo, &["add", "."]);
    git_cmd(&src_repo, &["commit", "-m", "base"]);
    let b_sha = GitOid::from_hex(&git_cmd(&src_repo, &["rev-parse", "HEAD"])).unwrap();

    // Branch A modifies line 1; Branch B modifies line 3 (clean 3-way merge, or conflict test).
    git_cmd(&src_repo, &["checkout", "-b", "pr-1"]);
    fs::write(src_repo.join("file.txt"), "PR1_TOP\nline2\nline3\n").unwrap();
    git_cmd(&src_repo, &["commit", "-am", "pr1-c1"]);
    fs::write(src_repo.join("extra.txt"), "pr1-c2\n").unwrap();
    git_cmd(&src_repo, &["add", "extra.txt"]);
    git_cmd(&src_repo, &["commit", "-m", "pr1-c2"]);
    let pr1_head = GitOid::from_hex(&git_cmd(&src_repo, &["rev-parse", "HEAD"])).unwrap();

    // Also create a synthetic `gh-readonly-queue/main/...` REBASE chain `B -> S1 -> S2`!
    git_cmd(&src_repo, &["checkout", "-b", "queue", &b_sha.to_hex()]);
    git_cmd(
        &src_repo,
        &["cherry-pick", &format!("{}~1", pr1_head.to_hex())],
    );
    let s1 = GitOid::from_hex(&git_cmd(&src_repo, &["rev-parse", "HEAD"])).unwrap();
    git_cmd(&src_repo, &["cherry-pick", &pr1_head.to_hex()]);
    let s2 = GitOid::from_hex(&git_cmd(&src_repo, &["rev-parse", "HEAD"])).unwrap();

    // Fetch into `HardenedBareGit` and run `merge_tree_clean` + `BareGitSliceReplayer` (`REBASE`).
    let bare_dir = td.path().join("bare.git");
    let bare =
        HardenedBareGit::init_bare(&bare_dir, Some(src_repo.display().to_string()), None).unwrap();
    bare.fetch_oid(&b_sha, 10).unwrap();
    bare.fetch_oid(&pr1_head, 10).unwrap();
    bare.fetch_oid(&s2, 10).unwrap();

    let merged_tree = bare
        .merge_tree_clean(&b_sha, &b_sha, &pr1_head)
        .unwrap()
        .expect("clean bare merge-tree must succeed");
    assert_eq!(merged_tree, bare.commit_tree_oid(&s2).unwrap());
    assert!(
        !sentinel.exists(),
        "CRITICAL: bare merge-tree must NEVER execute .gitattributes merge.<name>.driver!"
    );

    // Verify 2-commit `REBASE` slice replay matches `[B, S1, S2]` tree-for-tree!
    let chain_commits = vec![b_sha, s1, s2];
    let chain_trees: Vec<GitOid> = chain_commits
        .iter()
        .map(|c| bare.commit_tree_oid(c).unwrap())
        .collect();
    let replayer =
        BareGitSliceReplayer::new(&bare, MergeMethod::Rebase, &chain_commits, &chain_trees);
    let entry = MergeQueueEntry {
        pr_number: 1,
        head_oid: pr1_head,
        base_oid: Some(b_sha),
        state: MergeQueueEntryState::AwaitingChecks,
    };
    assert_eq!(replayer.try_replay_entry(0, &entry).unwrap(), Some(2));

    // Verify stacked-PR (`gh stack`) local-ref ancestry deepening (`refs/ci-core/pr-base`)
    // and `merge_base_with_deepening(main, stacked_merge)` anchoring back to `main`!
    git_cmd(
        &src_repo,
        &["checkout", "-b", "stack-2", &pr1_head.to_hex()],
    );
    fs::write(src_repo.join("stack2.txt"), "upper-stack\n").unwrap();
    git_cmd(&src_repo, &["add", "stack2.txt"]);
    git_cmd(&src_repo, &["commit", "-m", "stack2-c1"]);
    let stack2_head = GitOid::from_hex(&git_cmd(&src_repo, &["rev-parse", "HEAD"])).unwrap();

    // Create synthetic PR merge commit (`parents = [pr1_head, stack2_head]`).
    git_cmd(&src_repo, &["checkout", "--detach", &pr1_head.to_hex()]);
    git_cmd(
        &src_repo,
        &[
            "merge",
            "--no-ff",
            "-m",
            "Merge stack-2 into pr-1",
            &stack2_head.to_hex(),
        ],
    );
    let stack2_merge = GitOid::from_hex(&git_cmd(&src_repo, &["rev-parse", "HEAD"])).unwrap();

    let pr_base_tip = bare
        .fetch_ref("refs/heads/pr-1", "refs/ci-core/pr-base", 1)
        .unwrap();
    assert_eq!(pr_base_tip, pr1_head);
    bare.fetch_oid(&stack2_merge, 2).unwrap();
    bare.ensure_ancestor_with_deepening(&pr1_head, "refs/ci-core/pr-base")
        .unwrap();
    let tcb_anchor = bare
        .merge_base_with_deepening(&b_sha, &stack2_merge)
        .unwrap();
    assert_eq!(
        tcb_anchor, b_sha,
        "stacked PR TCB base must anchor to merge_base(default_branch, event_sha)"
    );
}

// ---------------------------------------------------------------------------
// 2. Obligation O6: Pure OCI Layout Verification & Hybrid Rejection
// ---------------------------------------------------------------------------

#[test]
fn o6_verify_oci_layout_unwraps_index_strips_docker_manifest_json_and_rejects_extras() {
    let td = tempfile::tempdir().unwrap();
    let layout = td.path().join("oci");
    let blobs = layout.join("blobs/sha256");
    fs::create_dir_all(&blobs).unwrap();
    fs::write(
        layout.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();

    let cfg_bytes = br#"{"architecture":"amd64","os":"linux","config":{"Env":["PATH=/usr/bin"]}}"#;
    let cfg_sha = Sha256Digest::hash_bytes(cfg_bytes);
    fs::write(blobs.join(cfg_sha.to_hex()), cfg_bytes).unwrap();

    let layer_bytes = b"layer-tar-payload";
    let layer_sha = Sha256Digest::hash_bytes(layer_bytes);
    fs::write(blobs.join(layer_sha.to_hex()), layer_bytes).unwrap();

    let img_manifest = serde_json::to_vec(&serde_json::json!({
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
    let manifest_sha = Sha256Digest::hash_bytes(&img_manifest);
    fs::write(blobs.join(manifest_sha.to_hex()), &img_manifest).unwrap();

    // Wrap inside a nested single-entry OCI Image Index + Docker 28 legacy `manifest.json`!
    let nested_index = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": manifest_sha.to_oci_digest(),
            "size": img_manifest.len()
        }]
    }))
    .unwrap();
    let nested_idx_sha = Sha256Digest::hash_bytes(&nested_index);
    fs::write(blobs.join(nested_idx_sha.to_hex()), &nested_index).unwrap();
    fs::write(
        layout.join("index.json"),
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "digest": nested_idx_sha.to_oci_digest(),
                "size": nested_index.len()
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(layout.join("manifest.json"), b"[{\"Config\":\"evil\"}]").unwrap();
    fs::write(layout.join("repositories"), b"{}").unwrap();

    // Raw `verify_oci_layout` MUST reject hybrid layout containing `manifest.json` (`O6`)!
    assert!(
        verify_oci_layout(&layout, &manifest_sha).is_err(),
        "O6: verify_oci_layout must reject hybrid layout containing legacy manifest.json"
    );

    // `normalize_docker_save_to_pure_oci` strips `manifest.json`/`repositories` + unreferenced
    // nested index blob and produces a pure single-manifest OCI layout!
    let norm = normalize_docker_save_to_pure_oci(&layout).unwrap();
    assert_eq!(norm.manifest_digest, manifest_sha);
    assert_eq!(norm.verified_config_digest, cfg_sha);
    assert!(!layout.join("manifest.json").exists());
    assert!(!blobs.join(nested_idx_sha.to_hex()).exists());

    // Now `verify_oci_layout` succeeds against `manifest_sha` and rejects `M' != M` or extra blobs!
    let verified = verify_oci_layout(&layout, &manifest_sha).unwrap();
    assert_eq!(verified.verified_config_digest, cfg_sha);
    assert!(verify_oci_layout(&layout, &Sha256Digest::hash_bytes(b"wrong")).is_err());

    fs::write(
        blobs.join(Sha256Digest::hash_bytes(b"extra").to_hex()),
        b"extra",
    )
    .unwrap();
    assert!(
        verify_oci_layout(&layout, &manifest_sha).is_err(),
        "O6: unreferenced blob in blobs/sha256 must fail closed"
    );
}

/// Legacy v1 image JSON that Docker 28.0.4's classic-store `docker save`
/// writes for the bottom layer of any image built `FROM`
/// `ubuntu:24.04@sha256:9a04f13b…` (amd64, layer diff ID
/// `sha256:369ede38…`). Its SHA-256 is the `64b3cae2…` blob that four
/// different x86-64 `build-image` jobs reported as unexpected.
const DOCKER28_UBUNTU2404_AMD64_LAYER0_V1_JSON: &[u8] = br#"{"id":"e7faef61ec7c9315d70cd9ef86ad5c3989eb698a2b318b27824c09d500d532b8","created":"1970-01-01T00:00:00Z","container_config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":null,"Cmd":null,"Image":"","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"os":"linux"}"#;

struct ClassicDockerSave {
    _td: tempfile::TempDir,
    layout: PathBuf,
    manifest_sha: Sha256Digest,
    cfg_sha: Sha256Digest,
    layer_shas: Vec<Sha256Digest>,
    legacy_v1_shas: Vec<Sha256Digest>,
}

/// Writes the directory shape that `docker save` produces on Docker
/// 28.0.4 with the classic image store (GitHub `ubuntu-24.04` runners):
/// `index.json` naming one OCI manifest (with image-name annotations),
/// uncompressed layer blobs, the config blob, `manifest.json`,
/// `repositories`, and one unreferenced legacy v1 JSON blob per layer.
fn write_docker28_classic_save_layout() -> ClassicDockerSave {
    let td = tempfile::tempdir().unwrap();
    let layout = td.path().join("oci");
    let blobs = layout.join("blobs/sha256");
    fs::create_dir_all(&blobs).unwrap();
    fs::write(
        layout.join("oci-layout"),
        br#"{"imageLayoutVersion": "1.0.0"}"#,
    )
    .unwrap();

    let put = |bytes: &[u8]| {
        let sha = Sha256Digest::hash_bytes(bytes);
        fs::write(blobs.join(sha.to_hex()), bytes).unwrap();
        sha
    };

    let layers: [&[u8]; 3] = [b"base-layer-tar", b"apt-layer-tar", b"rustup-layer-tar"];
    let layer_shas: Vec<Sha256Digest> = layers.iter().map(|l| put(l)).collect();

    let diff_ids: Vec<String> = layer_shas.iter().map(Sha256Digest::to_oci_digest).collect();
    let cfg_bytes = serde_json::to_vec(&serde_json::json!({
        "architecture": "amd64",
        "os": "linux",
        "config": {"Env": ["PATH=/usr/local/cargo/bin:/usr/bin"]},
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
    }))
    .unwrap();
    let cfg_sha = put(&cfg_bytes);

    let layer_descs: Vec<serde_json::Value> = layers
        .iter()
        .zip(&layer_shas)
        .map(|(bytes, sha)| {
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": sha.to_oci_digest(),
                "size": bytes.len(),
            })
        })
        .collect();
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": cfg_sha.to_oci_digest(),
            "size": cfg_bytes.len(),
        },
        "layers": layer_descs,
    }))
    .unwrap();
    let manifest_sha = put(&manifest);

    let mut legacy_v1_shas = vec![put(DOCKER28_UBUNTU2404_AMD64_LAYER0_V1_JSON)];
    for (i, parent) in ["e7faef61", "a1b2c3d4"].iter().enumerate() {
        let v1 = format!(
            r#"{{"id":"layer{i}","parent":"{parent}","created":"1970-01-01T00:00:00Z","os":"linux"}}"#
        );
        legacy_v1_shas.push(put(v1.as_bytes()));
    }

    fs::write(
        layout.join("index.json"),
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_sha.to_oci_digest(),
                "size": manifest.len(),
                "annotations": {
                    "io.containerd.image.name": "docker.io/library/ci-core-build:8866daca336bd3c5",
                    "org.opencontainers.image.ref.name": "8866daca336bd3c5",
                },
            }],
        }))
        .unwrap(),
    )
    .unwrap();
    let layer_paths: Vec<String> = layer_shas
        .iter()
        .map(|s| format!("blobs/sha256/{}", s.to_hex()))
        .collect();
    fs::write(
        layout.join("manifest.json"),
        serde_json::to_vec(&serde_json::json!([{
            "Config": format!("blobs/sha256/{}", cfg_sha.to_hex()),
            "RepoTags": ["ci-core-build:8866daca336bd3c5"],
            "Layers": layer_paths,
        }]))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        layout.join("repositories"),
        br#"{"ci-core-build":{"8866daca336bd3c5":"e7faef61"}}"#,
    )
    .unwrap();

    ClassicDockerSave {
        _td: td,
        layout,
        manifest_sha,
        cfg_sha,
        layer_shas,
        legacy_v1_shas,
    }
}

fn layout_files(layout: &Path) -> BTreeSet<String> {
    fn walk(root: &Path, cur: &Path, out: &mut BTreeSet<String>) {
        for ent in fs::read_dir(cur).unwrap() {
            let p = ent.unwrap().path();
            if p.is_dir() {
                walk(root, &p, out);
            } else {
                out.insert(p.strip_prefix(root).unwrap().to_str().unwrap().to_owned());
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(layout, layout, &mut out);
    out
}

#[test]
fn o6_normalize_prunes_docker28_classic_store_legacy_v1_layer_blobs() {
    let s = write_docker28_classic_save_layout();
    assert_eq!(
        s.legacy_v1_shas[0].to_hex(),
        "64b3cae297e41b0aeb2d25fa75f42e1d13a82f01df5bcafeacdb2a750340fc9d",
        "fixture must reproduce the legacy blob seen on real runners"
    );
    // The unpruned layout is exactly what failed on the runners.
    assert!(verify_oci_layout(&s.layout, &s.manifest_sha).is_err());

    let norm = normalize_docker_save_to_pure_oci(&s.layout).unwrap();
    assert_eq!(norm.manifest_digest, s.manifest_sha);
    assert_eq!(norm.verified_config_digest, s.cfg_sha);
    assert_eq!(
        norm.config_env,
        vec!["PATH=/usr/local/cargo/bin:/usr/bin".to_owned()]
    );
    let content: Vec<Sha256Digest> = norm.content_blobs.iter().map(|(d, _)| *d).collect();
    let mut want = vec![s.cfg_sha];
    want.extend(&s.layer_shas);
    assert_eq!(content, want);

    let mut expected: BTreeSet<String> = ["oci-layout", "index.json"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    for d in std::iter::once(&s.manifest_sha)
        .chain(std::iter::once(&s.cfg_sha))
        .chain(&s.layer_shas)
    {
        expected.insert(format!("blobs/sha256/{}", d.to_hex()));
    }
    assert_eq!(layout_files(&s.layout), expected);

    // The pruned layout passes the strict verifier used by every consumer.
    verify_oci_layout(&s.layout, &s.manifest_sha).unwrap();
}

#[test]
fn o6_docker_load_stream_carries_manifest_json_for_classic_store() {
    let s = write_docker28_classic_save_layout();
    let verified = normalize_docker_save_to_pure_oci(&s.layout).unwrap();
    let mj = verified.docker_load_manifest_json().unwrap();

    // Apply the checks Docker 28's classic `docker load` makes on a
    // `manifest.json` entry, and confirm the image ID it would assign.
    let items: Vec<serde_json::Value> = serde_json::from_slice(&mj).unwrap();
    assert_eq!(items.len(), 1);
    let item = &items[0];
    assert_eq!(item["RepoTags"], serde_json::json!([]));
    let cfg_bytes = fs::read(s.layout.join(item["Config"].as_str().unwrap())).unwrap();
    assert_eq!(Sha256Digest::hash_bytes(&cfg_bytes), s.cfg_sha);
    let cfg: serde_json::Value = serde_json::from_slice(&cfg_bytes).unwrap();
    let diff_ids = cfg["rootfs"]["diff_ids"].as_array().unwrap();
    let layers = item["Layers"].as_array().unwrap();
    assert_eq!(layers.len(), diff_ids.len());
    for (layer, diff_id) in layers.iter().zip(diff_ids) {
        let bytes = fs::read(s.layout.join(layer.as_str().unwrap())).unwrap();
        assert_eq!(
            Sha256Digest::hash_bytes(&bytes).to_oci_digest(),
            diff_id.as_str().unwrap()
        );
    }

    // The stream holds the verified layout plus `manifest.json`; the
    // on-disk layout stays pure OCI.
    let tar_bytes = write_docker_load_tar(&s.layout, &mj, Vec::new()).unwrap();
    let mut archive = tar::Archive::new(tar_bytes.as_slice());
    let mut streamed = BTreeSet::new();
    for ent in archive.entries().unwrap() {
        let mut ent = ent.unwrap();
        if !ent.header().entry_type().is_file() {
            continue;
        }
        let path = ent.path().unwrap().to_str().unwrap().to_owned();
        if path == "manifest.json" {
            let mut got = Vec::new();
            std::io::Read::read_to_end(&mut ent, &mut got).unwrap();
            assert_eq!(got, mj);
        }
        streamed.insert(path);
    }
    let mut expected = layout_files(&s.layout);
    assert!(!expected.contains("manifest.json"));
    expected.insert("manifest.json".to_owned());
    assert_eq!(streamed, expected);
    verify_oci_layout(&s.layout, &s.manifest_sha).unwrap();
}

#[test]
fn o6_normalize_still_rejects_malformed_docker_save_layouts() {
    type Mutate = fn(&ClassicDockerSave);
    let blob = |s: &ClassicDockerSave, name: &str| s.layout.join("blobs/sha256").join(name);
    let cases: [(&str, Mutate); 7] = [
        ("unreferenced symlink blob", |s| {
            let target = s.layout.join("blobs/sha256").join(s.layer_shas[0].to_hex());
            let name = Sha256Digest::hash_bytes(b"link").to_hex();
            symlink(target, s.layout.join("blobs/sha256").join(name)).unwrap();
        }),
        ("directory inside blobs/sha256", |s| {
            let dir = s
                .layout
                .join("blobs/sha256")
                .join(Sha256Digest::hash_bytes(b"dir").to_hex());
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("payload"), b"x").unwrap();
        }),
        ("non-hex file in blobs/sha256", |s| {
            fs::write(s.layout.join("blobs/sha256/not-a-digest"), b"x").unwrap();
        }),
        ("blob under another algorithm", |s| {
            fs::create_dir_all(s.layout.join("blobs/sha512")).unwrap();
            fs::write(s.layout.join("blobs/sha512/abcd"), b"x").unwrap();
        }),
        ("stray top-level file", |s| {
            fs::write(s.layout.join("extra"), b"x").unwrap();
        }),
        ("tampered referenced layer", |s| {
            let p = s.layout.join("blobs/sha256").join(s.layer_shas[1].to_hex());
            fs::write(p, b"evil-layer-tar").unwrap();
        }),
        ("second index.json entry", |s| {
            let p = s.layout.join("index.json");
            let mut idx: serde_json::Value =
                serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
            let first = idx["manifests"][0].clone();
            idx["manifests"].as_array_mut().unwrap().push(first);
            fs::write(p, serde_json::to_vec(&idx).unwrap()).unwrap();
        }),
    ];
    for (what, mutate) in cases {
        let s = write_docker28_classic_save_layout();
        mutate(&s);
        assert!(
            normalize_docker_save_to_pure_oci(&s.layout).is_err(),
            "O6: normalize must fail closed on {what}"
        );
        // Referenced content is never pruned away by a failed normalize.
        assert!(blob(&s, &s.manifest_sha.to_hex()).exists(), "{what}");
    }
}

#[test]
fn o6_normalize_never_prunes_through_symlinked_blob_dirs() {
    for link_level in ["blobs", "blobs/sha256"] {
        let s = write_docker28_classic_save_layout();
        let outside = s
            .layout
            .parent()
            .unwrap()
            .join(format!("outside-{}", link_level.replace('/', "-")));
        let moved = s.layout.join(link_level);
        fs::rename(&moved, &outside).unwrap();
        symlink(&outside, &moved).unwrap();
        let legacy_rel = s.legacy_v1_shas[0].to_hex();
        let legacy_outside = if link_level == "blobs" {
            outside.join("sha256").join(&legacy_rel)
        } else {
            outside.join(&legacy_rel)
        };
        assert!(legacy_outside.exists());
        assert!(
            normalize_docker_save_to_pure_oci(&s.layout).is_err(),
            "O6: normalize must reject a symlinked `{link_level}`"
        );
        assert!(
            legacy_outside.exists(),
            "O6: normalize must not unlink through a symlinked `{link_level}`"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Real `/usr/bin/bwrap` NestedBwrap Confinement (`EROFS`, `CLONE_NEWNET`,
//    Inner `bwrap --unshare-all`, Writable Overlay, Env Stripping & Outputs)
// ---------------------------------------------------------------------------

fn copy_elf_with_shared_libs(elf_path: &Path, rootfs: &Path, dest_rel: &str) {
    let dst = rootfs.join(dest_rel.trim_start_matches('/'));
    fs::create_dir_all(dst.parent().unwrap()).unwrap();
    fs::copy(elf_path, &dst).unwrap();
    fs::set_permissions(&dst, fs::Permissions::from_mode(0o755)).unwrap();

    let out = Command::new("ldd").arg(elf_path).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        for tok in line.split_whitespace() {
            if tok.starts_with('/') && Path::new(tok).exists() {
                let lib_dst = rootfs.join(tok.trim_start_matches('/'));
                if !lib_dst.exists() {
                    fs::create_dir_all(lib_dst.parent().unwrap()).unwrap();
                    fs::copy(tok, &lib_dst).unwrap();
                }
            }
        }
    }
}

#[test]
fn live_nested_bwrap_enforces_erofs_netns_env_stripping_and_allows_inner_bwrap() {
    let Ok(bwrap_bin) = resolve_bwrap_binary() else {
        eprintln!("skipping bwrap test: bwrap binary not installed");
        return;
    };
    if let Err(e) = verify_bwrap_userns_preflight(&bwrap_bin) {
        eprintln!("skipping bwrap test: unprivileged userns unavailable on host ({e})");
        return;
    }

    let td = tempfile::tempdir().unwrap();
    let probe_src = td.path().join("sandbox_probe.rs");
    let probe_bin = td.path().join("sandbox_probe");
    fs::write(
        &probe_src,
        r#"
use std::env;
use std::fs::{self, OpenOptions};
use std::net::UdpSocket;
use std::process::Command;

fn assert_erofs(path: &str) {
    let err = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .expect_err("expected /work to be read-only (EROFS)");
    // EROFS == 30 on Linux
    assert_eq!(err.raw_os_error(), Some(30), "unexpected errno on {path}: {err:?}");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("inner") {
        assert_erofs("/work/inner_write_attempt.txt");
        return;
    }
    if args.get(1).map(String::as_str) == Some("env_cleared") {
        assert!(env::var("HOME").is_err(), "HOME must be unset in env_cleared child");
        assert_eq!(
            env::home_dir().as_deref(),
            Some(std::path::Path::new("/scratch")),
            "synthesized /etc/passwd must resolve getpwuid_r(getuid()) to /scratch"
        );
        return;
    }

    // 1. Read-only `/work` (`EROFS`) while declared `/work/gen` overlay is writable.
    assert_eq!(fs::read_to_string("/work/sub/input.txt").unwrap(), "hermetic-input\n");
    assert_erofs("/work/sub/readonly_probe.txt");
    fs::write("/work/gen/generated.txt", b"overlay-ok\n").unwrap();

    // 2. Inner `/usr/bin/bwrap --unshare-all --cap-drop ALL` succeeds while `MNT_LOCK_READONLY` holds!
    let inner = Command::new("/usr/bin/bwrap")
        .args([
            "--ro-bind", "/", "/",
            "--dev", "/dev",
            "--proc", "/proc",
            "--ro-bind", "/work", "/work",
            "--unshare-all",
            "--cap-drop", "ALL",
            "--",
            "/usr/bin/sandbox_probe", "inner",
        ])
        .status()
        .expect("failed to launch inner bwrap");
    assert!(inner.success(), "inner bwrap --unshare-all failed: {inner}");

    // 3. `CLONE_NEWNET`: outbound UDP connect/send fails (`ENETUNREACH`).
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    assert!(
        sock.send_to(b"ping", "8.8.8.8:53").is_err(),
        "CLONE_NEWNET must block outbound network traffic"
    );

    // 4. Environment isolation: `GITHUB_TOKEN`/`LD_PRELOAD` stripped, `PIN_*` & `HOME=/scratch` injected.
    assert!(env::var("GITHUB_TOKEN").is_err());
    assert!(env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").is_err());
    assert!(env::var("LD_PRELOAD").is_err());
    assert_eq!(env::var("HOME").unwrap(), "/scratch");
    assert_eq!(env::var("PIN_KANI_PIN__TOOL_VERSION").unwrap(), "0.61.0");
    assert_eq!(env::var("CHECK_CUSTOM").unwrap(), "expected-val");

    // 5. Writable `/scratch`, cache mount `/cargo-home`, and `/outputs`.
    fs::write("/scratch/tmp.txt", b"scratch").unwrap();
    fs::write("/cargo-home/marker.txt", b"cached").unwrap();
    fs::write("/outputs/lcov.info", b"TN:\nend_of_record\n").unwrap();

    // 6. Subprocesses that call `env_clear()` (`HOME` unset) resolve `pw_dir = "/scratch"`.
    let cleared = Command::new("/usr/bin/sandbox_probe")
        .arg("env_cleared")
        .env_clear()
        .status()
        .expect("failed to launch env_cleared probe");
    assert!(cleared.success(), "env_cleared getpwuid_r probe failed: {cleared}");
}
"#,
    )
    .unwrap();

    let rustc_st = Command::new("rustc")
        .args(["--edition=2024", "-O"])
        .arg(&probe_src)
        .arg("-o")
        .arg(&probe_bin)
        .status()
        .expect("rustc must be available");
    assert!(rustc_st.success(), "failed to compile sandbox_probe.rs");

    let rootfs = td.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    copy_elf_with_shared_libs(&bwrap_bin, &rootfs, "/usr/bin/bwrap");
    copy_elf_with_shared_libs(&probe_bin, &rootfs, "/usr/bin/sandbox_probe");

    let work_dir = td.path().join("work");
    fs::create_dir_all(work_dir.join("sub")).unwrap();
    fs::create_dir_all(work_dir.join("gen")).unwrap();
    fs::write(work_dir.join("sub/input.txt"), b"hermetic-input\n").unwrap();

    let overlay_host = td.path().join("overlay-gen");
    fs::create_dir_all(&overlay_host).unwrap();
    let scratch_dir = td.path().join("scratch");
    fs::create_dir_all(&scratch_dir).unwrap();
    let outputs_dir = td.path().join("outputs");
    fs::create_dir_all(&outputs_dir).unwrap();
    let cache_dir = td.path().join("cache-cargo");
    fs::create_dir_all(&cache_dir).unwrap();

    let oci_env = vec![
        "PATH=/usr/bin:/bin".to_owned(),
        "GITHUB_TOKEN=leaked-from-image".to_owned(),
        "LD_PRELOAD=/evil.so".to_owned(),
    ];
    let mut check_env = BTreeMap::new();
    check_env.insert("CHECK_CUSTOM".to_owned(), "expected-val".to_owned());
    let mut pin_vals = BTreeMap::new();
    pin_vals.insert(PinKey::new("tool_version").unwrap(), "0.61.0".to_owned());
    let mut pins = BTreeMap::new();
    pins.insert(PinId::new("kani-pin").unwrap(), pin_vals);
    let merged_env = build_sandbox_env(&oci_env, &check_env, &pins, "/scratch", "/tmp");

    let overlays = vec![(overlay_host, RepoRelPath::new("gen").unwrap())];
    let cache_mounts = vec![(cache_dir.clone(), AbsUnixPath::new("/cargo-home").unwrap())];
    let wd = RepoRelPath::new("sub").unwrap();
    let cmd = vec!["/usr/bin/sandbox_probe".to_owned()];

    let launch = SandboxLaunchSpec {
        work_dir: &work_dir,
        writable_overlays: &overlays,
        scratch_dir: &scratch_dir,
        outputs_dir: &outputs_dir,
        cache_mounts: &cache_mounts,
        workdir: Some(&wd),
        command: &cmd,
        merged_env: &merged_env,
    };

    let passed = run_nested_bwrap_sandbox(&bwrap_bin, &rootfs, &launch).unwrap();
    assert!(passed, "live NestedBwrap probe exited non-zero");

    // Verify `O_NOFOLLOW` output capture succeeds on `/outputs/lcov.info`!
    let lcov_name = OutputName::new("lcov.info").unwrap();
    let mut declared = BTreeMap::new();
    declared.insert(
        lcov_name.clone(),
        DeclaredOutputSpec {
            name: lcov_name,
            max_bytes: 1024,
        },
    );
    let captured = capture_declared_outputs(&outputs_dir, &declared, None).unwrap();
    assert_eq!(
        captured[&OutputName::new("lcov.info").unwrap()],
        OutputDigest {
            sha256: Sha256Digest::hash_bytes(b"TN:\nend_of_record\n"),
            size_bytes: 18,
        }
    );
}

// ---------------------------------------------------------------------------
// 4. O_NOFOLLOW Output Capture & Cache Pack/Hydrate Hardlink/Symlink Guards
// ---------------------------------------------------------------------------

#[test]
fn onofollow_outputs_and_cache_pack_hydrate_enforce_hardlink_and_symlink_confinement() {
    let td = tempfile::tempdir().unwrap();

    // A. `capture_declared_outputs` rejects symlink & external hardlink!
    let out_sym = td.path().join("out-sym");
    fs::create_dir_all(&out_sym).unwrap();
    symlink("/etc/passwd", out_sym.join("lcov.info")).unwrap();
    let lcov_name = OutputName::new("lcov.info").unwrap();
    let mut declared = BTreeMap::new();
    declared.insert(
        lcov_name.clone(),
        DeclaredOutputSpec {
            name: lcov_name,
            max_bytes: 100_000,
        },
    );
    assert!(
        capture_declared_outputs(&out_sym, &declared, None).is_err(),
        "O_NOFOLLOW must reject symlinked declared output"
    );

    let out_hl = td.path().join("out-hl");
    fs::create_dir_all(&out_hl).unwrap();
    let ext_secret = td.path().join("secret.txt");
    fs::write(&ext_secret, b"top-secret").unwrap();
    fs::hard_link(&ext_secret, out_hl.join("lcov.info")).unwrap();
    assert!(
        capture_declared_outputs(&out_hl, &declared, None).is_err(),
        "nlink == 1 check must reject hardlinked declared output"
    );

    // B. `pack_cache_archive` + `hydrate_cache_archive` preserves internal hardlinks,
    // skips `.package-cache`/`.global-cache` on `cargo_locked`, and rejects external hardlinks!
    let cdir = td.path().join("cache-good");
    fs::create_dir_all(cdir.join("sub")).unwrap();
    fs::write(cdir.join("a.bin"), b"shared-inode-bytes").unwrap();
    fs::hard_link(cdir.join("a.bin"), cdir.join("sub/b.bin")).unwrap();
    symlink("../a.bin", cdir.join("sub/rel_link")).unwrap();
    fs::write(cdir.join(".package-cache"), b"lock-1").unwrap();
    fs::write(cdir.join(".global-cache"), b"sqlite-1").unwrap();

    let arch1 = td.path().join("c1.tar.zst");
    let (dig1, sz1) = pack_cache_archive(&cdir, &arch1, 1_000_000, true)
        .unwrap()
        .expect("non-empty cache archive");
    // Mutating Cargo's transient `.package-cache` produces the EXACT SAME `Sha256Digest`!
    fs::write(cdir.join(".package-cache"), b"lock-2-changed").unwrap();
    let arch2 = td.path().join("c2.tar.zst");
    let (dig2, _) = pack_cache_archive(&cdir, &arch2, 1_000_000, true)
        .unwrap()
        .unwrap();
    assert_eq!(
        dig1, dig2,
        "cargo_locked cache pack must ignore .package-cache churn"
    );
    assert!(sz1 > 0);

    let hydrated = td.path().join("hydrated");
    hydrate_cache_archive(&arch1, &hydrated, 1_000_000).unwrap();
    assert_eq!(
        fs::read(hydrated.join("sub/b.bin")).unwrap(),
        b"shared-inode-bytes"
    );
    assert_eq!(
        fs::read_link(hydrated.join("sub/rel_link")).unwrap(),
        PathBuf::from("../a.bin")
    );
    assert!(!hydrated.join(".package-cache").exists());

    // External hardlink (`internal_link_count == 1 != st_nlink == 2`) -> rejected!
    let cdir_ext_hl = td.path().join("cache-ext-hl");
    fs::create_dir_all(&cdir_ext_hl).unwrap();
    fs::hard_link(&ext_secret, cdir_ext_hl.join("leaked.txt")).unwrap();
    assert!(
        pack_cache_archive(
            &cdir_ext_hl,
            &td.path().join("bad.tar.zst"),
            1_000_000,
            false
        )
        .is_err(),
        "external hardlink into cache_dir must fail internal_link_count == st_nlink"
    );
}

// ---------------------------------------------------------------------------
// 5. Obligation O9: Live Isolated-`cwd` `cargo fetch --locked` (`RUSTUP_HOME`
//    Preserved, Malicious Repo `.cargo/config.toml` Wrapper Neutralized)
// ---------------------------------------------------------------------------

#[test]
fn o9_isolated_cwd_cargo_locked_fetch_preserves_rustup_home_and_ignores_repo_cargo_config() {
    let td = tempfile::tempdir().unwrap();
    let repo = td.path().join("repo");
    let ws = repo.join("ws");
    fs::create_dir_all(ws.join("src")).unwrap();

    let canary = td.path().join("WRAPPER_RAN");
    let wrapper = td.path().join("evil_wrapper.sh");
    fs::write(
        &wrapper,
        format!("#!/bin/sh\ntouch {}\nexit 1\n", canary.display()),
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();

    // Malicious `.cargo/config.toml` at both repo root and `ws/.cargo/config.toml`!
    fs::create_dir_all(repo.join(".cargo")).unwrap();
    fs::write(
        repo.join(".cargo/config.toml"),
        format!(
            "[build]\nrustc-wrapper = {:?}\n[env]\nLD_PRELOAD = \"/nonexistent_evil.so\"\n",
            wrapper.display().to_string()
        ),
    )
    .unwrap();
    fs::create_dir_all(ws.join(".cargo")).unwrap();
    fs::write(
        ws.join(".cargo/config.toml"),
        format!("[build]\nrustc = {:?}\n", wrapper.display().to_string()),
    )
    .unwrap();

    // Also include `readme = "../NONEXISTENT_README.md"` (unmaterialized outside `<fetch_src>`)
    // and a `build.rs` (materialized as a 0-byte stub, never executed by `cargo fetch`)!
    fs::write(
        ws.join("Cargo.toml"),
        "[package]\nname = \"fetch_iso\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
         readme = \"../NONEXISTENT_README.md\"\n",
    )
    .unwrap();
    fs::write(
        ws.join("src/lib.rs"),
        "compile_error!(\"must be 0-byte stub\");\n",
    )
    .unwrap();
    fs::write(
        ws.join("build.rs"),
        "fn main() { panic!(\"must not execute\"); }\n",
    )
    .unwrap();
    fs::write(
        ws.join("Cargo.lock"),
        "# This file is automatically @generated by Cargo.\nversion = 4\n\n\
         [[package]]\nname = \"fetch_iso\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();

    let tree = LocalWorktree::new(&repo).unwrap();
    let mut allowed = BTreeMap::new();
    allowed.insert(
        "crates-io".to_owned(),
        RegistryIndexUrl::new("registry+https://github.com/rust-lang/crates.io-index").unwrap(),
    );
    let fetch_plan =
        audit_cargo_locked(&tree, &RepoRelPath::new("ws/Cargo.toml").unwrap(), &allowed).unwrap();

    let cache_dir = td.path().join("cargo-cache");
    let staging = td.path().join("staging");
    run_cargo_locked_fetch_native(&fetch_plan, &allowed, &cache_dir, &staging, &["--offline"])
        .expect("O9: isolated-cwd cargo fetch --locked must succeed with RUSTUP_HOME preserved");

    assert!(
        !canary.exists(),
        "CRITICAL: isolated-cwd cargo fetch must NEVER execute repo .cargo/config.toml wrappers!"
    );
}

// ---------------------------------------------------------------------------
// 6. Bottom-Up Claim Commit Order (`isha256 -> ksha256 -> asha256`), Layer 0
//    Bundle Deduplication & OIDC JWT Pre-Sign Validation
// ---------------------------------------------------------------------------

#[test]
fn bottom_up_claim_commit_orders_i_then_k_then_a_and_deduplicates_bundle_blob() {
    let reg = InMemoryRegistry::new();
    let bundle_bytes =
        b"{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\"}".to_vec();
    let bundle_dig = Sha256Digest::hash_bytes(&bundle_bytes);
    let bundle_ref = BlobRef {
        digest: bundle_dig,
        bytes: bundle_bytes,
    };

    let c_img = Claim::Image {
        recipe: Sha256Digest::hash_bytes(b"r1"),
        manifest: Sha256Digest::hash_bytes(b"m1"),
    };
    let c_cache = Claim::Cache {
        key: Sha256Digest::hash_bytes(b"k1"),
        slot: CacheSlotId::new("cargo").unwrap(),
        archive: Sha256Digest::hash_bytes(b"arch-bytes"),
        size_bytes: 10,
        provenance_signers: BTreeSet::new(),
    };
    let c_chk1 = Claim::Check {
        action: Sha256Digest::hash_bytes(b"a1"),
        outputs: BTreeMap::new(),
        provenance_signers: BTreeSet::new(),
    };
    let c_chk2 = Claim::Check {
        action: Sha256Digest::hash_bytes(b"a2"),
        outputs: BTreeMap::new(),
        provenance_signers: BTreeSet::new(),
    };

    // Pre-upload cache payload blob to `PrivateCache` as `upload_verified_blob` does in `publish`.
    let arch_file = tempfile::NamedTempFile::new().unwrap();
    fs::write(arch_file.path(), b"arch-bytes").unwrap();
    reg.upload_verified_blob(
        StoreTier::PrivateCache,
        arch_file.path(),
        &Sha256Digest::hash_bytes(b"arch-bytes"),
        10,
    )
    .unwrap();

    let s_img = StagedClaim::new(StoreTier::PublicCas, &c_img, Vec::new()).unwrap();
    let s_cache = StagedClaim::new(
        StoreTier::PrivateCache,
        &c_cache,
        vec![BlobDescriptor {
            digest: Sha256Digest::hash_bytes(b"arch-bytes"),
            size_bytes: 10,
            media_type: "application/vnd.ci-core.cache.v1.tar+zstd".to_owned(),
            title: None,
        }],
    )
    .unwrap();
    let s_chk1 = StagedClaim::new(StoreTier::PublicCas, &c_chk1, Vec::new()).unwrap();
    let s_chk2 = StagedClaim::new(StoreTier::PublicCas, &c_chk2, Vec::new()).unwrap();

    commit_claims_bottom_up(&reg, &bundle_ref, &[s_img], &[s_cache], &[s_chk1, s_chk2]).unwrap();

    let order = reg.committed_tags_order();
    assert_eq!(
        order,
        vec![
            (StoreTier::PublicCas, c_img.lookup_tag()),
            (StoreTier::PrivateCache, c_cache.lookup_tag()),
            (StoreTier::PublicCas, c_chk1.lookup_tag()),
            (StoreTier::PublicCas, c_chk2.lookup_tag()),
        ]
    );
    // 3 claims were committed to `PublicCas`, yet `Layer 0` (`bundle_ref`) was uploaded ONLY ONCE!
    assert_eq!(
        reg.bundle_upload_count(StoreTier::PublicCas, &bundle_dig),
        1
    );
    assert_eq!(
        reg.bundle_upload_count(StoreTier::PrivateCache, &bundle_dig),
        1
    );

    // Read-only discovery degradation: `401`/`403` on `PublicCas` or `PrivateCache` degrades to `Ok(None)`!
    let denied_reg = InMemoryRegistry::new().with_read_denial(true, true);
    assert!(
        denied_reg
            .fetch_claim_artifact(
                StoreTier::PublicCas,
                &LookupTag::image_claim(&Sha256Digest::hash_bytes(b"r1"))
            )
            .unwrap()
            .is_none()
    );

    // OIDC JWT pre-sign guard rejects private repo visibility under `SigstoreRoot::PublicGood`!
    use base64::Engine as _;
    let url_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let s_sha = "1111111111111111111111111111111111111111";
    let hdr = url_b64.encode(b"{\"alg\":\"RS256\"}");
    let claims_priv = url_b64.encode(
        serde_json::to_vec(&serde_json::json!({
            "iss": "https://token.actions.githubusercontent.com",
            "job_workflow_sha": s_sha,
            "job_workflow_ref": format!("joshlf/ci-core/.github/workflows/ci.yml@{s_sha}"),
            "repository_id": "100",
            "repository_owner_id": "200",
            "repository_visibility": "private"
        }))
        .unwrap(),
    );
    let jwt = format!("{hdr}.{claims_priv}.sig");
    let pol = SignerPolicy {
        repo_id: 100,
        owner_id: 200,
        default_branch: "main".to_owned(),
        oidc_issuer: "https://token.actions.githubusercontent.com".to_owned(),
        sigstore: SigstoreRoot::PublicGood,
        trusted_engine_workflow: WorkflowUri::new("joshlf/ci-core/.github/workflows/ci.yml")
            .unwrap(),
        trusted_pr_workflow: WorkflowUri::new("joshlf/ci-core/.github/workflows/ci-pr.yml")
            .unwrap(),
        trusted_review_signal_workflow: WorkflowUri::new(
            "joshlf/ci-core/.github/workflows/review-signal.yml",
        )
        .unwrap(),
        trusted_review_rerun_workflow: WorkflowUri::new(
            "joshlf/ci-core/.github/workflows/review-rerun.yml",
        )
        .unwrap(),
        trusted_engine_shas: NonEmptyVec::singleton(GitOid::from_hex(s_sha).unwrap()),
    };
    assert!(
        validate_actions_oidc_jwt_claims(&jwt, &pol).is_err(),
        "PublicGood signer must refuse private repository OIDC JWTs"
    );
}

#[test]
fn extract_tar_stripping_special_preserves_nix_0555_executables_and_cleans_up() {
    let td = tempfile::tempdir().unwrap();
    let tar_path = td.path().join("nix-rootfs.tar");
    {
        let f = fs::File::create(&tar_path).unwrap();
        let mut tb = tar::Builder::new(f);

        // Simulate a read-only `0o555` Nix store directory and `0o555` executable
        // script, plus a `0o4755` setuid file whose setuid bit must be stripped.
        let mut dir_hdr = tar::Header::new_gnu();
        dir_hdr.set_entry_type(tar::EntryType::Directory);
        dir_hdr.set_mode(0o555);
        dir_hdr.set_size(0);
        dir_hdr.set_cksum();
        tb.append_data(&mut dir_hdr, "nix/store/demo/bin", std::io::empty())
            .unwrap();

        let script = b"#!/bin/sh\nexit 0\n";
        let mut bin_hdr = tar::Header::new_gnu();
        bin_hdr.set_entry_type(tar::EntryType::Regular);
        bin_hdr.set_mode(0o555);
        bin_hdr.set_size(script.len() as u64);
        bin_hdr.set_cksum();
        tb.append_data(&mut bin_hdr, "nix/store/demo/bin/tool", &script[..])
            .unwrap();

        let mut suid_hdr = tar::Header::new_gnu();
        suid_hdr.set_entry_type(tar::EntryType::Regular);
        suid_hdr.set_mode(0o4755);
        suid_hdr.set_size(script.len() as u64);
        suid_hdr.set_cksum();
        tb.append_data(&mut suid_hdr, "nix/store/demo/bin/suid-tool", &script[..])
            .unwrap();

        let mut ro_hdr = tar::Header::new_gnu();
        ro_hdr.set_entry_type(tar::EntryType::Regular);
        ro_hdr.set_mode(0o444);
        ro_hdr.set_size(4);
        ro_hdr.set_cksum();
        tb.append_data(&mut ro_hdr, "nix/store/demo/data.txt", &b"data"[..])
            .unwrap();

        tb.finish().unwrap();
    }

    let rootfs = td.path().join("extracted");
    extract_tar_stripping_special(&tar_path, &rootfs).unwrap();

    let tool_mode = fs::metadata(rootfs.join("nix/store/demo/bin/tool"))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        tool_mode, 0o755,
        "0o555 Nix executable must retain execute bits (0o755), got {tool_mode:#o}"
    );

    let suid_mode = fs::metadata(rootfs.join("nix/store/demo/bin/suid-tool"))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        suid_mode, 0o755,
        "0o4755 binary must have setuid stripped to 0o755, got {suid_mode:#o}"
    );

    let data_mode = fs::metadata(rootfs.join("nix/store/demo/data.txt"))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        data_mode, 0o644,
        "0o444 non-executable file must become 0o644 without gaining execute bits"
    );

    // Must cleanly remove `rootfs` without EACCES from `0o555` directories.
    fs::remove_dir_all(&rootfs).unwrap();
}

#[test]
fn podman_build_uses_docker_format_for_shell_directives() {
    let rt = ContainerRuntime::Podman {
        bin: PathBuf::from("/usr/bin/podman"),
        rootless: true,
    };
    let args = rt.build_image_args(
        "linux/amd64",
        "https://github.com/example/repo",
        "ci-core-test:tag",
        Path::new("ci/docker/test.Dockerfile"),
        &[("PIN_FOO__BAR".to_owned(), "1.0.0".to_owned())],
        Path::new("."),
    );
    let fmt_idx = args
        .iter()
        .position(|a| a == "--format")
        .expect("podman build must pass --format");
    assert_eq!(
        args.get(fmt_idx + 1).map(String::as_str),
        Some("docker"),
        "podman build must use `--format docker` so Dockerfile SHELL directives are honored"
    );
}

#[test]
fn globset_link_header_www_authenticate_uname_and_openat2_materialization_work() {
    use ci_core_cli::ghcr::parse_bearer_www_authenticate;
    use ci_core_cli::github_api::parse_link_next_url;
    use ci_core_cli::sandbox::{materialize_work_closure, verify_host_platform};
    use ci_core_model::tree::{
        InMemoryTree, compile_selector_glob, filter_paths_by_globs, validate_source_closure,
    };
    use ci_core_model::types::Platform;

    // 1. `globset`: `dir/**` matches both direct child `dir/a.rs` and nested `dir/sub/b.rs`,
    // and rejects `{a,b}` brace alternation.
    assert!(compile_selector_glob("src/{a,b}.rs").is_err());
    let paths = [
        RepoRelPath::new("dir/a.rs").unwrap(),
        RepoRelPath::new("dir/sub/b.rs").unwrap(),
        RepoRelPath::new("dir/.hidden").unwrap(),
        RepoRelPath::new("other/c.rs").unwrap(),
    ];
    let matched =
        filter_paths_by_globs(&paths, &["dir/**".to_owned()], &["**/sub/**".to_owned()]).unwrap();
    assert_eq!(matched.len(), 2);
    assert!(matched.contains(&RepoRelPath::new("dir/a.rs").unwrap()));
    assert!(matched.contains(&RepoRelPath::new("dir/.hidden").unwrap()));

    // 2. RFC 8288 `Link` header handles commas inside `<...>` and space-separated `rel`.
    let link = r#"<https://api.github.com/items?filter=a,b&page=1>; rel="prev", <https://api.github.com/items?filter=a,b&page=2>; rel="next prefetch""#;
    assert_eq!(
        parse_link_next_url(link).as_deref(),
        Some("https://api.github.com/items?filter=a,b&page=2")
    );

    // 3. RFC 7235 `WWW-Authenticate: Bearer` parser handles quoted `realm` and `service`.
    let www = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/ubuntu:pull""#;
    assert_eq!(
        parse_bearer_www_authenticate(www),
        Some((
            "https://auth.docker.io/token".to_owned(),
            Some("registry.docker.io".to_owned())
        ))
    );

    // 4. `rustix::system::uname()` matches host architecture with zero subprocess fork
    // and fails closed on a mismatched target architecture.
    #[cfg(target_arch = "x86_64")]
    let (host_platform, other_platform) = (Platform::LinuxAmd64, Platform::LinuxArm64);
    #[cfg(target_arch = "aarch64")]
    let (host_platform, other_platform) = (Platform::LinuxArm64, Platform::LinuxAmd64);
    verify_host_platform(host_platform).unwrap();
    assert!(matches!(
        verify_host_platform(other_platform),
        Err(ci_core_cli::sandbox::SandboxError::ArchMismatch { .. })
    ));

    // 5. `materialize_work_closure` writes files & symlinks via fd-relative `openat`/`symlinkat`
    // (exercising `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` on repeated parent opens).
    let mut mem_tree = InMemoryTree::new();
    mem_tree.insert_executable("bin/run.sh", b"#!/bin/sh\nexit 0\n".to_vec());
    mem_tree.insert_file("bin/data.txt", b"hello\n".to_vec());
    mem_tree.insert_symlink("bin/alias.txt", "data.txt");
    let closure_set: BTreeSet<RepoRelPath> = [
        RepoRelPath::new("bin/run.sh").unwrap(),
        RepoRelPath::new("bin/data.txt").unwrap(),
        RepoRelPath::new("bin/alias.txt").unwrap(),
    ]
    .into_iter()
    .collect();
    let validated = validate_source_closure(&mem_tree, &closure_set, None, &[]).unwrap();
    let td = tempfile::tempdir().unwrap();
    let work = td.path().join("work");
    materialize_work_closure(
        &mem_tree,
        &validated,
        &work,
        &[RepoRelPath::new("target").unwrap()],
        Some(&RepoRelPath::new("bin").unwrap()),
    )
    .unwrap();
    assert_eq!(
        fs::metadata(work.join("bin/run.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        fs::read_link(work.join("bin/alias.txt")).unwrap().to_str(),
        Some("data.txt")
    );
    assert!(work.join("target").is_dir());
}
