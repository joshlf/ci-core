//! Property-based (`proptest`) and exhaustive adversarial verification tests
//! for `ci-core-model`: `evaluate_gate`, `O1`/`O1b` owner approvals, `O2`
//! workflow anti-spoofing, `O4` cache staging, `O5` `CODEOWNERS` dominance,
//! `O7` review-rerun polling, `PinId`/`PinKey` injectivity, `EffectiveTcb`,
//! and stepwise `merge_group` attribution.

use std::collections::{BTreeMap, BTreeSet};

use ci_core_model::config::{ChecksConfig, ControlPlaneHeader, validate_config_against_tree};
use ci_core_model::digest::{ActionPreimage, CacheMountBinding, ImageRecipePreimage};
use ci_core_model::engine::{
    BuiltImageMeta, CheckExecStatus, CheckExecutionOutcome, CompletedRunJobs, EvalStage,
    ExecutionPlan, GateError, GatePass, ImagePlan, InflightRunAction, InflightRunSnapshot,
    ObservedJobResults, PendingImageBuild, ReviewRerunDecision, ScheduledCheckPlan, ShardMeta,
    UpstreamJobResult, classify_inflight_run_poll, decide_review_rerun, evaluate_gate,
    pack_execute_shards, resolve_attempt_records, should_attempt_cache_pack,
};
use ci_core_model::store::{MergeQueueEntry, MergeQueueEntryState, PrReview, PrReviewState};
use ci_core_model::tcb::{
    CommitSliceReplayer, PathTrustClass, TcbError, TcbPlan, caller_allowed_effective,
    classify_under_joined_tcb, compute_effective_tcb, evaluate_merge_group_tcb, evaluate_pr_tcb,
    has_relevant_review_for_stage2, is_owner_approved, validate_codeowners, validate_workflows,
    verify_engine_workflows, verify_landed_prefix,
};
use ci_core_model::tree::{
    ConfinedEntry, InMemoryTree, SourceTree, validate_confined_dir, validate_source_closure,
};
use ci_core_model::types::{
    AbsUnixPath, CheckId, ControlPlaneTransition, GitOid, ImageId, NonEmptyVec, OutputName, PinId,
    PinKey, Platform, ReferencedWorkflow, RepoRelPath, RepoSlug, RunMode, SandboxMode,
    Sha256Digest, TriggerEvent, UnixSecs, WorkflowRunMeta, pin_env_var_name,
};
use proptest::prelude::*;

const S1: &str = "1111111111111111111111111111111111111111";
const S2: &str = "2222222222222222222222222222222222222222";
const C1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const C2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const C3: &str = "cccccccccccccccccccccccccccccccccccccccc";

fn oid(s: &str) -> GitOid {
    GitOid::from_hex(s).unwrap()
}

fn minimal_repo_tree(checks_toml: &str) -> InMemoryTree {
    let mut t = InMemoryTree::new();
    t.insert_file("ci/checks.toml", checks_toml.as_bytes().to_vec());
    t.insert_file(".github/CODEOWNERS", b"* @google/owners\n".to_vec());
    t.insert_file(
        ".github/workflows/ci.yml",
        format!(
            r#"name: ci
on:
  pull_request: {{}}
  merge_group: {{}}
  push:
    branches: [main]
permissions:
  actions: read
  contents: read
  packages: write
  id-token: write
  pull-requests: read
jobs:
  ci:
    name: ci
    uses: joshlf/ci-core/.github/workflows/ci.yml@{S1}
    with:
      config_path: ci/checks.toml
      shadow_mode: false
"#
        )
        .into_bytes(),
    );
    t.insert_file(
        ".github/workflows/ci-review-signal.yml",
        format!(
            r#"name: ci-review-signal
on:
  pull_request_review:
    types: [submitted, dismissed]
permissions: {{}}
jobs:
  signal:
    name: review-signal
    uses: joshlf/ci-core/.github/workflows/review-signal.yml@{S1}
"#
        )
        .into_bytes(),
    );
    t.insert_file(
        ".github/workflows/ci-review-rerun.yml",
        format!(
            r#"name: ci-review-rerun
on:
  workflow_run:
    workflows: [ci-review-signal]
    types: [completed]
permissions:
  actions: write
  contents: read
  pull-requests: read
jobs:
  rerun:
    name: review-rerun
    uses: joshlf/ci-core/.github/workflows/review-rerun.yml@{S1}
    with:
      config_path: ci/checks.toml
"#
        )
        .into_bytes(),
    );
    t.insert_file("ci/pins/kani.toml", b"version = \"0.61.0\"\n".to_vec());
    t.insert_file(
        "ci/docker/base.Dockerfile",
        b"FROM ubuntu@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782\n"
            .to_vec(),
    );
    t.insert_file("ci/scripts/run.sh", b"#!/bin/sh\nexit 0\n".to_vec());
    t.insert_file(
        "src/lib.rs",
        b"pub fn add(a: i32, b: i32) -> i32 { a + b }\n".to_vec(),
    );
    t
}

fn minimal_checks_toml(extra_checks_block: &str) -> String {
    format!(
        r#"schema_version = 1

[repo]
slug = "google/demo"
id = 100
owner_id = 200
default_branch = "main"
sigstore = "public_good"
trusted_engine_workflow = "joshlf/ci-core/.github/workflows/ci.yml"
trusted_engine_shas = ["{S1}"]

[tcb]
owner_user_ids = [10, 20]
allow_owner_self_approval = false
review_signal_workflow = ".github/workflows/ci-review-signal.yml"
review_rerun_workflow = ".github/workflows/ci-review-rerun.yml"
non_tcb_workflows = ["scorecard.yml"]
non_tcb_subtrees = ["evals", "vendor"]
extra_executable_paths = ["ci/scripts/**"]

[tcb.caller]
kind = "repo_ruleset"
caller_workflows = [".github/workflows/ci.yml"]
gate_check_name = "ci / gate"
codeowners = ["@google/owners"]

[pins.kani]
path = "ci/pins/kani.toml"
keys = {{ version = "[0-9]+\\.[0-9]+\\.[0-9]+" }}

[images.base]
dockerfile = "ci/docker/base.Dockerfile"
platform = "linux/amd64"
runner = "ubuntu-24.04"

[[checks]]
id = "unit"
image = "base"
runner = "ubuntu-24.04"
inputs = [{{ kind = "glob", include = ["src/**"] }}]
command = ["cargo", "test"]
{extra_checks_block}
"#
    )
}

// ---------------------------------------------------------------------------
// 1. Property Tests: PinId / PinKey Injective PIN_* Projection & Slug Parity
// ---------------------------------------------------------------------------

fn arb_pin_token() -> impl Strategy<Value = String> {
    prop::collection::vec("[a-z0-9]{1,8}", 1..=12).prop_flat_map(|segs| {
        let n = segs.len();
        prop::collection::vec(
            prop_oneof![Just("-"), Just("_")],
            (n - 1)..=n.saturating_sub(1),
        )
        .prop_map(move |seps| {
            let mut out = segs[0].clone();
            for (sep, seg) in seps.into_iter().zip(segs.iter().skip(1)) {
                out.push_str(sep);
                out.push_str(seg);
            }
            if out.len() > 128 {
                out.truncate(128);
                while out.ends_with('-') || out.ends_with('_') {
                    out.pop();
                }
            }
            out
        })
    })
}

#[test]
fn pin_token_allows_long_cargo_keys_up_to_128_bytes() {
    let long_key = PinKey::new("no-zerocopy-panic-in-const-and-vec-try-reserve-1-57-0")
        .expect("53-byte real-world Cargo build-rs probe key must be accepted");
    let pin = PinId::new("rust-toolchains").unwrap();
    assert_eq!(
        pin_env_var_name(&pin, &long_key),
        "PIN_RUST_TOOLCHAINS__NO_ZEROCOPY_PANIC_IN_CONST_AND_VEC_TRY_RESERVE_1_57_0"
    );
    assert!(PinKey::new(&"a".repeat(128)).is_ok());
    assert!(PinKey::new(&"a".repeat(129)).is_err());
    assert!(PinKey::new("bad--sep").is_err());
    assert!(PinKey::new("bad__sep").is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn prop_pin_env_projection_has_zero_cross_separator_collisions(
        p1_s in arb_pin_token(),
        k1_s in arb_pin_token(),
        p2_s in arb_pin_token(),
        k2_s in arb_pin_token(),
    ) {
        let p1 = PinId::new(&p1_s).unwrap();
        let k1 = PinKey::new(&k1_s).unwrap();
        let p2 = PinId::new(&p2_s).unwrap();
        let k2 = PinKey::new(&k2_s).unwrap();

        let env1 = pin_env_var_name(&p1, &k1);
        let env2 = pin_env_var_name(&p2, &k2);

        let norm = |s: &str| s.to_ascii_uppercase().replace('-', "_");
        prop_assert!(!norm(p1.as_str()).contains("__"));
        prop_assert!(!norm(k1.as_str()).contains("__"));

        let same_norm_components =
            norm(p1.as_str()) == norm(p2.as_str()) && norm(k1.as_str()) == norm(k2.as_str());
        prop_assert_eq!(env1 == env2, same_norm_components);
    }

    #[test]
    fn prop_shard_packer_bounds_at_256_and_preserves_homogeneity_and_exact_once_checks(
        check_specs in prop::collection::vec(
            (0usize..4, prop::bool::ANY, 0usize..3),
            1..=350
        )
    ) {
        let runners = ["ubuntu-24.04", "ubuntu-24.04-arm", "linux-large", "linux-xl"];
        let img_names = ["img-a", "img-b", "img-c"];

        let mut images = BTreeMap::new();
        for (i, name) in img_names.iter().enumerate() {
            let id = ImageId::new(name).unwrap();
            let rec = Sha256Digest::hash_bytes(name.as_bytes());
            let dummy_pre = ImageRecipePreimage::new(
                RepoRelPath::new("ci/docker/base.Dockerfile").unwrap(),
                rec,
                rec,
                BTreeMap::new(),
                BTreeMap::new(),
                Platform::LinuxAmd64,
                "https://github.com/google/demo".to_owned(),
            );
            if i % 2 == 0 {
                images.insert(
                    id,
                    ImagePlan::PendingBuild {
                        recipe: rec,
                        preimage: dummy_pre,
                        runner: "ubuntu-24.04".to_owned(),
                        platform: Platform::LinuxAmd64,
                    },
                );
            } else {
                images.insert(
                    id,
                    ImagePlan::Reused {
                        recipe: rec,
                        manifest: Sha256Digest::hash_bytes(b"m"),
                        bundle_sha256: Sha256Digest::hash_bytes(b"b"),
                        raw_claim_bytes: Vec::new(),
                    },
                );
            }
        }

        let mut scheduled = BTreeMap::new();
        for (idx, (r_idx, use_bwrap, img_idx)) in check_specs.into_iter().enumerate() {
            let cid = CheckId::new(&format!("chk-{idx:04}")).unwrap();
            let sb = if use_bwrap { SandboxMode::NestedBwrap } else { SandboxMode::Container };
            let img_id = ImageId::new(img_names[img_idx]).unwrap();
            let runner = runners[r_idx].to_owned();
            let preimage = ActionPreimage {
                check_id: cid.clone(),
                source_merkle: Sha256Digest::hash_bytes(b"src"),
                platform: Platform::LinuxAmd64,
                sandbox: sb,
                writable_dirs: Vec::new(),
                workdir: None,
                command: vec!["true".to_owned()],
                env: BTreeMap::new(),
                pins: BTreeMap::new(),
                cache_mounts: Vec::new(),
                declared_outputs: Vec::new(),
            };
            scheduled.insert(cid.clone(), ScheduledCheckPlan {
                check_id: cid,
                image_id: img_id,
                runner,
                sandbox: sb,
                shard_group: None,
                action_preimage: preimage,
                caches: BTreeMap::new(),
            });
        }

        let shards = pack_execute_shards(&scheduled, &images).unwrap();
        prop_assert!(shards.len() <= 256);

        let mut seen = BTreeSet::new();
        for shard in &shards {
            for chk in shard.checks.iter() {
                let sp = &scheduled[chk];
                prop_assert_eq!(&sp.runner, &shard.runner);
                prop_assert_eq!(sp.sandbox, shard.sandbox);
                prop_assert_eq!(&sp.image_id, &shard.image_id);
                prop_assert_eq!(shard.needs_bwrap, shard.sandbox == SandboxMode::NestedBwrap);
                prop_assert!(seen.insert(chk.clone()), "duplicate check `{chk}` across shards");
            }
        }
        prop_assert_eq!(seen.len(), scheduled.len());
    }

    #[test]
    fn prop_o1_owner_approval_projection_never_resurrects_superseded_comment_approvals(
        events in prop::collection::vec(
            (
                prop_oneof![Just(10u64), Just(20u64), Just(999u64)],
                0u8..6,
                prop_oneof![Just(C1), Just(C2), Just(C3)],
            ),
            0..=20
        )
    ) {
        let mut reviews = Vec::new();
        for (idx, (uid, kind, sha_s)) in events.into_iter().enumerate() {
            let c_oid = oid(sha_s);
            let (state, body) = match kind {
                0 => (PrReviewState::Approved, String::new()),
                1 => (PrReviewState::ChangesRequested, String::new()),
                2 => (PrReviewState::Dismissed, String::new()),
                3 => (PrReviewState::Commented, format!("/ci-core approve {sha_s}")),
                4 => (PrReviewState::Commented, "/ci-core unapprove".to_owned()),
                _ => (PrReviewState::Commented, "looks good".to_owned()),
            };
            reviews.push(PrReview {
                review_id: (idx as u64) + 1,
                user_id: uid,
                state,
                commit_id: Some(c_oid),
                body,
                submitted_at: UnixSecs(1000 + (idx as u64)),
            });
        }

        let target = oid(C1);
        let res_self_ok = is_owner_approved(&reviews, &[10, 20], true, &target);

        // Reference oracle directly from `ci_core_design_spec.md` §4.3 + `O1`:
        // Project independently of `target` FIRST, pick latest per owner, then
        // check `state == Approved && commit_id == Some(target)` and zero owner
        // `ChangesRequested`.
        let mut oracle_latest: BTreeMap<u64, (PrReviewState, Option<GitOid>)> = BTreeMap::new();
        for r in &reviews {
            if r.user_id != 10 && r.user_id != 20 {
                continue;
            }
            let proj = match r.state {
                PrReviewState::Approved | PrReviewState::ChangesRequested | PrReviewState::Dismissed => {
                    Some((r.state, r.commit_id))
                }
                PrReviewState::Commented => {
                    let b = r.body.trim();
                    if b == "/ci-core unapprove" {
                        Some((PrReviewState::Dismissed, r.commit_id))
                    } else if let Some(rest) = b.strip_prefix("/ci-core approve ") {
                        if let Ok(p_oid) = GitOid::from_hex(rest.trim()) {
                            if r.commit_id == Some(p_oid) {
                                Some((PrReviewState::Approved, Some(p_oid)))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                PrReviewState::Pending => None,
            };
            if let Some(p) = proj {
                oracle_latest.insert(r.user_id, p);
            }
        }
        let has_veto = oracle_latest.values().any(|(st, _)| *st == PrReviewState::ChangesRequested);
        let has_app = oracle_latest
            .values()
            .any(|(st, c)| *st == PrReviewState::Approved && *c == Some(target));
        prop_assert_eq!(res_self_ok, has_app && !has_veto);
    }
}

// ---------------------------------------------------------------------------
// 2. Targeted Adversarial Unit Tests: O1, O1b, O2, O4, O5, O7
// ---------------------------------------------------------------------------

#[test]
fn o1_and_o1b_force_push_back_c1_c2_c1_and_stage2_relevance_hold() {
    let c1 = oid(C1);
    let c2 = oid(C2);

    // Owner 10 self-approves C1 at t=1, then self-approves C2 at t=2, then force-pushes PR back to C1.
    let reviews_c2_supersedes = vec![
        PrReview {
            review_id: 1,
            user_id: 10,
            state: PrReviewState::Commented,
            commit_id: Some(c1),
            body: format!("/ci-core approve {C1}"),
            submitted_at: UnixSecs(10),
        },
        PrReview {
            review_id: 2,
            user_id: 10,
            state: PrReviewState::Commented,
            commit_id: Some(c2),
            body: format!("/ci-core approve {C2}"),
            submitted_at: UnixSecs(20),
        },
    ];
    assert!(
        !is_owner_approved(&reviews_c2_supersedes, &[10], true, &c1),
        "O1: force-push-back C1 -> C2 -> C1 must NOT resurrect older /ci-core approve C1"
    );
    assert!(is_owner_approved(&reviews_c2_supersedes, &[10], true, &c2));

    // `/ci-core unapprove` submitted on C2 revokes C1 even after force-push-back to C1.
    let reviews_unapprove_on_c2 = vec![
        PrReview {
            review_id: 1,
            user_id: 10,
            state: PrReviewState::Commented,
            commit_id: Some(c1),
            body: format!("/ci-core approve {C1}"),
            submitted_at: UnixSecs(10),
        },
        PrReview {
            review_id: 2,
            user_id: 10,
            state: PrReviewState::Commented,
            commit_id: Some(c2),
            body: "/ci-core unapprove".to_owned(),
            submitted_at: UnixSecs(20),
        },
    ];
    assert!(!is_owner_approved(
        &reviews_unapprove_on_c2,
        &[10],
        true,
        &c1
    ));

    // When `allow_self_approval == false`, `/ci-core approve` is rejected.
    assert!(!is_owner_approved(
        &reviews_c2_supersedes[..1],
        &[10],
        false,
        &c1
    ));

    // O1b: Stage 2 relevance recognizes `/ci-core unapprove` from owner 10 unconditionally,
    // while ignoring non-owner spam comments/approvals.
    assert!(has_relevant_review_for_stage2(
        &reviews_unapprove_on_c2[1..],
        &[10]
    ));
    let spam_reviews = vec![
        PrReview {
            review_id: 9,
            user_id: 9999,
            state: PrReviewState::Approved,
            commit_id: Some(c1),
            body: "/ci-core unapprove".to_owned(),
            submitted_at: UnixSecs(30),
        },
        PrReview {
            review_id: 10,
            user_id: 10,
            state: PrReviewState::Commented,
            commit_id: Some(c1),
            body: "ordinary review comment".to_owned(),
            submitted_at: UnixSecs(31),
        },
    ];
    assert!(!has_relevant_review_for_stage2(&spam_reviews, &[10]));
}

#[test]
fn o2_validate_workflows_blocks_job_uses_gate_spoofing_and_supports_1pr_caller_split() {
    let config_path = RepoRelPath::new("ci/checks.toml").unwrap();
    let base_toml = minimal_checks_toml("");
    let cfg = ChecksConfig::parse_toml(&base_toml, &config_path).unwrap();

    // 1. Baseline valid tree passes `validate_workflows` (with safe `scorecard.yml`).
    let mut tree = minimal_repo_tree(&base_toml);
    tree.insert_file(
        ".github/workflows/scorecard.yml",
        br#"name: Scorecard
on:
  push:
    branches: [main]
permissions: {}
jobs:
  analysis:
    name: Scorecard analysis
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
      id-token: write
    steps:
      - run: "true"
"#
        .to_vec(),
    );
    validate_workflows(&tree, &cfg).expect("baseline workflows must pass");

    // 2. Obligation O2: a sibling `job.uses` job skipped via `if: false` and named `"ci / gate"`
    // MUST be rejected unconditionally!
    let mut spoof_uses_tree = tree.clone();
    spoof_uses_tree.insert_file(
        ".github/workflows/other.yml",
        format!(
            r#"name: Other
on: [pull_request]
permissions:
  contents: read
jobs:
  sneaky:
    name: "ci / gate"
    if: false
    uses: some-org/some-repo/.github/workflows/reusable.yml@{S2}
"#
        )
        .into_bytes(),
    );
    assert!(
        validate_workflows(&spoof_uses_tree, &cfg).is_err(),
        "O2: sibling job.uses named `ci / gate` must be rejected"
    );

    // 3. Reject `statuses: write` and `checks: write` and dynamic `${{ inputs.name }}` spoofing.
    for bad_wf in [
        r#"name: BadStatus
on: [pull_request]
permissions:
  statuses: write
jobs:
  j:
    runs-on: ubuntu-24.04
    steps: [{ run: "true" }]
"#,
        r#"name: BadDynamicName
on: [pull_request]
permissions:
  contents: read
jobs:
  j:
    name: "${{ github.event.head_commit.message }}"
    runs-on: ubuntu-24.04
    steps: [{ run: "true" }]
"#,
    ] {
        let mut bt = tree.clone();
        bt.insert_file(".github/workflows/bad.yml", bad_wf.as_bytes().to_vec());
        assert!(validate_workflows(&bt, &cfg).is_err());
    }

    // 4. 1-PR `caller_workflows = [".github/workflows/ci.yml", ".github/workflows/ci-trusted.yml"]`
    // disjoint trigger split passes with zero binary changes!
    let split_toml = base_toml.replace(
        "caller_workflows = [\".github/workflows/ci.yml\"]",
        "caller_workflows = [\".github/workflows/ci.yml\", \".github/workflows/ci-trusted.yml\"]",
    );
    let split_cfg = ChecksConfig::parse_toml(&split_toml, &config_path).unwrap();
    let mut split_tree = tree.clone();
    split_tree.insert_file("ci/checks.toml", split_toml.into_bytes());
    split_tree.insert_file(
        ".github/workflows/ci.yml",
        format!(
            r#"name: ci-pr
on:
  pull_request: {{}}
permissions:
  actions: read
  contents: read
  packages: read
  pull-requests: read
jobs:
  ci:
    name: ci
    uses: joshlf/ci-core/.github/workflows/ci.yml@{S1}
    with:
      shadow_mode: false
"#
        )
        .into_bytes(),
    );
    split_tree.insert_file(
        ".github/workflows/ci-trusted.yml",
        format!(
            r#"name: ci-trusted
on:
  merge_group: {{}}
  push:
    branches: [main]
permissions:
  actions: read
  contents: read
  packages: write
  id-token: write
  pull-requests: read
jobs:
  ci:
    name: ci
    uses: joshlf/ci-core/.github/workflows/ci.yml@{S1}
    with:
      shadow_mode: false
"#
        )
        .into_bytes(),
    );
    validate_workflows(&split_tree, &split_cfg).expect("1-PR caller split must pass");
}

#[test]
fn o5_validate_codeowners_enforces_backslash_ban_recursive_dominance_and_shadowing() {
    let base_toml = minimal_checks_toml("");
    let config_path = RepoRelPath::new("ci/checks.toml").unwrap();
    let cfg = ChecksConfig::parse_toml(&base_toml, &config_path).unwrap();
    let base_tree = minimal_repo_tree(&base_toml);

    validate_codeowners(&base_tree, &cfg, &config_path).expect("valid `* @google/owners` passes");

    // 1. O5: flat `\` ban catches gitignore `/\.github/workflows/exp.yml @other` escape!
    let mut bs_tree = base_tree.clone();
    bs_tree.insert_file(
        ".github/CODEOWNERS",
        b"* @google/owners\n/\\.github/workflows/exp.yml @other/team\n".to_vec(),
    );
    assert!(
        validate_codeowners(&bs_tree, &cfg, &config_path).is_err(),
        "O5: backslash in CODEOWNERS pattern must fail closed"
    );

    // 2. Root-only `"/*"` and slashless `"/.github"` do NOT satisfy recursive dominance!
    for non_recursive in [
        "/* @google/owners\n",
        "/.github @google/owners\n/ci/ @google/owners\n",
    ] {
        let mut t = base_tree.clone();
        t.insert_file(".github/CODEOWNERS", non_recursive.as_bytes().to_vec());
        assert!(validate_codeowners(&t, &cfg, &config_path).is_err());
    }

    // 3. `/CODEOWNERS` or `/docs/CODEOWNERS` shadowing is rejected!
    for shadow_path in ["CODEOWNERS", "docs/CODEOWNERS"] {
        let mut t = base_tree.clone();
        t.insert_file(shadow_path, b"* @google/owners\n".to_vec());
        assert!(validate_codeowners(&t, &cfg, &config_path).is_err());
    }

    // 4. Post-catch-all override on `/evals/** @other/team` (inside `non_tcb_subtrees`,
    // syntactically disjoint from `/.github/**` and all TCB/pin paths) is ALLOWED, while
    // `/.github/workflows/experimental.yml @other/team` or `/src/** @other/team` (where
    // synthetic `/__probe__/.cargo/config.toml` or depth-1 `.cargo` probes test root catch-all,
    // wait: `/src/foo` is untrusted, whereas `/ci/scripts/x.sh` is ExecutableTcb!)
    let mut allowed_sub_owner = base_tree.clone();
    allowed_sub_owner.insert_file(
        ".github/CODEOWNERS",
        b"* @google/owners\n/evals/** @other/eval-owners\n".to_vec(),
    );
    validate_codeowners(&allowed_sub_owner, &cfg, &config_path)
        .expect("/evals/** non-TCB delegation after `* @google/owners` must pass");

    let mut bad_post_github = base_tree.clone();
    bad_post_github.insert_file(
        ".github/CODEOWNERS",
        b"* @google/owners\n/.github/workflows/exp.yml @other/team\n".to_vec(),
    );
    assert!(validate_codeowners(&bad_post_github, &cfg, &config_path).is_err());
}

#[test]
fn o4_and_o7_cache_cold_miss_staging_and_review_rerun_polling_invariants() {
    let c0 = CheckId::new("miri--shard-0").unwrap();
    let c1 = CheckId::new("miri--shard-1").unwrap();
    let d1 = Sha256Digest::hash_bytes(b"arch1");

    // O4: When `c0` (`c_owner`) is in Shard 0 and `c1` runs in Shard 1 (`shard_checks = [c1]`),
    // `c1` IS allowed to stage a non-empty cold-miss archive (`publish` deduplicates by `c_updater`)!
    assert!(should_attempt_cache_pack(
        true,
        &c1,
        &c0,
        None,
        false,
        std::slice::from_ref(&c1)
    ));
    // Within the SAME shard `[c0, c1]`, if `c0` did not stage (`already_staged_in_shard == false`),
    // `c1` CAN still stage if `c0` left `<cache_dir>` empty, whereas if `already_staged_in_shard == true`,
    // `c1` skips duplicate staging!
    assert!(should_attempt_cache_pack(
        true,
        &c1,
        &c0,
        None,
        false,
        &[c0.clone(), c1.clone()]
    ));
    assert!(!should_attempt_cache_pack(
        true,
        &c1,
        &c0,
        None,
        true,
        &[c0.clone(), c1.clone()]
    ));
    // Warm hit (`Some(&d1)`) allows any passing check to pack on content change (unless PR `publish_eligible == false`).
    assert!(should_attempt_cache_pack(
        true,
        &c1,
        &c0,
        Some(&d1),
        false,
        &[c0.clone(), c1.clone()]
    ));
    assert!(!should_attempt_cache_pack(
        false,
        &c0,
        &c0,
        None,
        false,
        std::slice::from_ref(&c0)
    ));

    // O7: Post-`plan` `"queued"` downstream jobs MUST enter `PollUntilSettled`, NOT `LeaveUntouched`!
    assert_eq!(
        classify_inflight_run_poll(&InflightRunSnapshot {
            run_status: "in_progress".to_owned(),
            plan_status: Some("completed".to_owned()),
            build_images_status: Some("queued".to_owned()),
            execute_status: Some("queued".to_owned()),
        }),
        InflightRunAction::PollUntilSettled
    );
    assert_eq!(
        classify_inflight_run_poll(&InflightRunSnapshot {
            run_status: "in_progress".to_owned(),
            plan_status: Some("completed".to_owned()),
            build_images_status: Some("completed".to_owned()),
            execute_status: Some("in_progress".to_owned()),
        }),
        InflightRunAction::LeaveUntouched
    );
    assert_eq!(
        classify_inflight_run_poll(&InflightRunSnapshot {
            run_status: "queued".to_owned(),
            plan_status: Some("queued".to_owned()),
            build_images_status: None,
            execute_status: None,
        }),
        InflightRunAction::LeaveUntouched
    );

    // ControlPlaneHeader forward-compatibility: unknown fields inside `[[checks]]` do NOT break
    // Stage-2 `review-rerun` control-plane extraction during a 1-PR engine + schema upgrade!
    let future_toml = format!(
        "{}\nfuture_v2_knob = true\n",
        minimal_checks_toml("").trim_end()
    );
    assert!(
        ChecksConfig::parse_toml(&future_toml, &RepoRelPath::new("ci/checks.toml").unwrap())
            .is_err()
    );
    let cp_hdr = ControlPlaneHeader::parse_toml(&future_toml)
        .expect("ControlPlaneHeader must ignore unknown check fields");
    assert_eq!(cp_hdr.control_plane().unwrap().signer.repo_id, 100);
}

// ---------------------------------------------------------------------------
// 3. EffectiveTcb Symlink/Subtree Hardening & Stepwise MergeQueue Replay
// ---------------------------------------------------------------------------

struct MapSliceReplayer {
    steps: BTreeMap<(usize, u64), usize>,
}

impl CommitSliceReplayer for MapSliceReplayer {
    fn try_replay_entry(
        &self,
        c_cur: usize,
        entry: &MergeQueueEntry,
    ) -> Result<Option<usize>, String> {
        Ok(self.steps.get(&(c_cur, entry.pr_number)).copied())
    }
}

#[test]
fn effective_tcb_and_merge_group_stepwise_attribution_block_reverts_and_piggybacking() {
    let base_toml = minimal_checks_toml("");
    let config_path = RepoRelPath::new("ci/checks.toml").unwrap();
    let cfg = ChecksConfig::parse_toml(&base_toml, &config_path).unwrap();
    let s0_tree = minimal_repo_tree(&base_toml);

    // 1. Symlink at `.cargo` or symlink `workdir` fails closed immediately!
    let mut bad_cargo_sym = s0_tree.clone();
    bad_cargo_sym.insert_symlink(".cargo", "evals");
    assert!(compute_effective_tcb(&cfg, &config_path, &[&bad_cargo_sym], &bad_cargo_sym).is_err());

    // 2. Cargo 1.82+ `include` from `.cargo/config.toml` into `evals/shared.toml` (inside
    // `non_tcb_subtrees`) unconditionally promotes `evals/shared.toml` to `ExecutableTcb`!
    let mut inc_tree = s0_tree.clone();
    inc_tree.insert_file(
        ".cargo/config.toml",
        b"include = \"../evals/shared.toml\"\n".to_vec(),
    );
    inc_tree.insert_file("evals/shared.toml", b"[build]\n".to_vec());
    let eff = compute_effective_tcb(&cfg, &config_path, &[&inc_tree], &inc_tree).unwrap();
    assert_eq!(
        classify_under_joined_tcb(&[eff], &RepoRelPath::new("evals/shared.toml").unwrap()),
        PathTrustClass::ExecutableTcb
    );

    // 3. Stepwise `merge_group` replay:
    // Case A: Intra-PR `REBASE` `X -> Y -> X` TCB revert (`S_0 -> S_1` edits `ci/scripts/run.sh`,
    // `S_1 -> S_2` reverts it back to `S_0`!). Two-dot `S_0..S_2` would see 0 diff, whereas
    // stepwise `evaluate_merge_group_tcb` catches `S_0 -> S_1` and requires PR #41 approval!
    let mut s1_tcb_edit = s0_tree.clone();
    s1_tcb_edit.insert_file("ci/scripts/run.sh", b"#!/bin/sh\necho pwn\n".to_vec());
    let mut s2_reverted = s0_tree.clone();
    s2_reverted.insert_file("src/lib.rs", b"pub fn ok() {}\n".to_vec());

    let t0 = oid("1000000000000000000000000000000000000000");
    let t1 = oid("2000000000000000000000000000000000000000");
    let t2 = oid("3000000000000000000000000000000000000000");
    let pr41_head = oid(C1);
    let pr42_head = oid(C2);

    let entries = vec![
        MergeQueueEntry {
            pr_number: 41,
            head_oid: pr41_head,
            base_oid: Some(t0),
            state: MergeQueueEntryState::AwaitingChecks,
        },
        // Queue depth `m > k`: trailing PR #42 beyond `E = S_2` must be ignored cleanly!
        MergeQueueEntry {
            pr_number: 42,
            head_oid: pr42_head,
            base_oid: Some(t2),
            state: MergeQueueEntryState::Queued,
        },
    ];
    let mut steps = BTreeMap::new();
    steps.insert((0, 41), 2); // REBASE 2 commits: S_0 -> S_1 -> S_2
    let replayer = MapSliceReplayer { steps };

    // Unapproved PR #41 -> rejected!
    let unapproved_res = evaluate_merge_group_tcb(
        &config_path,
        &cfg,
        &[&s0_tree, &s1_tcb_edit, &s2_reverted],
        &[t0, t1, t2],
        &[t0],
        &entries,
        &replayer,
        &|_| Ok(Vec::new()),
    );
    assert!(
        matches!(
            unapproved_res,
            Err(TcbError::MergeGroupRejected(ref msg)) if msg.contains("41")
        ),
        "intra-PR REBASE X->Y->X TCB revert without approval must fail closed: {unapproved_res:?}"
    );

    // Approved PR #41 -> `RequiresOwnerApproval { required_prs: [(41, C1)] }`!
    let approved_res = evaluate_merge_group_tcb(
        &config_path,
        &cfg,
        &[&s0_tree, &s1_tcb_edit, &s2_reverted],
        &[t0, t1, t2],
        &[t0],
        &entries,
        &replayer,
        &|pr| {
            assert_eq!(pr, 41, "trailing PR #42 beyond E must not even be queried");
            Ok(vec![PrReview {
                review_id: 1,
                user_id: 10,
                state: PrReviewState::Approved,
                commit_id: Some(pr41_head),
                body: String::new(),
                submitted_at: UnixSecs(100),
            }])
        },
    )
    .unwrap();
    assert_eq!(
        approved_res,
        TcbPlan::RequiresOwnerApproval {
            required_prs: NonEmptyVec::singleton((41, pr41_head)),
            control_plane_transition: None,
        }
    );

    // Case B: Two-PR forward-promotion piggybacking!
    // PR #51 (unapproved) writes `custom/hook.sh` (currently Untrusted under `S_0`).
    // PR #52 (approved by owner 10) adds `"custom/**"` to `extra_executable_paths` in `ci/checks.toml`!
    // Under `⊔ C_all`, `custom/hook.sh` is classified as `ExecutableTcb` on PR #51's slice too,
    // so PR #51 MUST also be owner-approved!
    let mut s1_piggy = s0_tree.clone();
    s1_piggy.insert_file("custom/hook.sh", b"#!/bin/sh\nmalicious\n".to_vec());
    let promoted_toml = base_toml.replace(
        "extra_executable_paths = [\"ci/scripts/**\"]",
        "extra_executable_paths = [\"ci/scripts/**\", \"custom/**\"]",
    );
    let mut s2_promote = s1_piggy.clone();
    s2_promote.insert_file("ci/checks.toml", promoted_toml.into_bytes());

    let entries_piggy = vec![
        MergeQueueEntry {
            pr_number: 51,
            head_oid: pr41_head,
            base_oid: Some(t0),
            state: MergeQueueEntryState::AwaitingChecks,
        },
        MergeQueueEntry {
            pr_number: 52,
            head_oid: pr42_head,
            base_oid: Some(t1),
            state: MergeQueueEntryState::Queued,
        },
    ];
    let mut steps_piggy = BTreeMap::new();
    steps_piggy.insert((0, 51), 1);
    steps_piggy.insert((1, 52), 1);
    let replayer_piggy = MapSliceReplayer { steps: steps_piggy };

    let piggy_res = evaluate_merge_group_tcb(
        &config_path,
        &cfg,
        &[&s0_tree, &s1_piggy, &s2_promote],
        &[t0, t1, t2],
        &[t0],
        &entries_piggy,
        &replayer_piggy,
        &|pr| {
            if pr == 52 {
                Ok(vec![PrReview {
                    review_id: 2,
                    user_id: 10,
                    state: PrReviewState::Approved,
                    commit_id: Some(pr42_head),
                    body: String::new(),
                    submitted_at: UnixSecs(100),
                }])
            } else {
                Ok(Vec::new())
            }
        },
    );
    assert!(
        matches!(
            piggy_res,
            Err(TcbError::MergeGroupRejected(ref msg)) if msg.contains("51")
        ),
        "forward-promotion piggybacking by unapproved PR #51 must fail closed: {piggy_res:?}"
    );

    // Case C: Contiguous landed-prefix check (`verify_landed_prefix`) rejects reverted/diverged `main`.
    assert!(verify_landed_prefix(&t0, &[t1, t2], &t0, &[t1]));
    assert!(!verify_landed_prefix(&t0, &[t1, t2], &t0, &[t2])); // M_1 != S_1
    assert!(!verify_landed_prefix(&t0, &[t1], &t0, &[t1, t2])); // q > k

    // Case D: Initial repo onboarding in `merge_group` (`S_0` lacks `ci/checks.toml`, `S_1` adds it)
    // requires live owner approval on the onboarding PR, while mid-chain deletion fails closed!
    let mut pre_onboard_tree = InMemoryTree::new();
    pre_onboard_tree.insert_file("src/lib.rs", b"pub fn pre() {}\n".to_vec());
    let onboard_entries = vec![MergeQueueEntry {
        pr_number: 61,
        head_oid: pr41_head,
        base_oid: Some(t0),
        state: MergeQueueEntryState::AwaitingChecks,
    }];
    let mut steps_onboard = BTreeMap::new();
    steps_onboard.insert((0, 61), 1);
    let replayer_onboard = MapSliceReplayer {
        steps: steps_onboard,
    };
    assert!(
        evaluate_merge_group_tcb(
            &config_path,
            &cfg,
            &[&pre_onboard_tree, &s0_tree],
            &[t0, t1],
            &[t0],
            &onboard_entries,
            &replayer_onboard,
            &|_| Ok(Vec::new()),
        )
        .is_err(),
        "unapproved initial onboarding PR in merge_group must fail closed"
    );
    let onboard_ok = evaluate_merge_group_tcb(
        &config_path,
        &cfg,
        &[&pre_onboard_tree, &s0_tree],
        &[t0, t1],
        &[t0],
        &onboard_entries,
        &replayer_onboard,
        &|_| {
            Ok(vec![PrReview {
                review_id: 9,
                user_id: 10,
                state: PrReviewState::Approved,
                commit_id: Some(pr41_head),
                body: String::new(),
                submitted_at: UnixSecs(100),
            }])
        },
    )
    .expect("owner-approved initial onboarding PR in merge_group must pass");
    assert_eq!(
        onboard_ok,
        TcbPlan::RequiresOwnerApproval {
            required_prs: NonEmptyVec::singleton((61, pr41_head)),
            control_plane_transition: None,
        }
    );

    // Deleting `ci/checks.toml` after it existed in `S_0` must fail closed immediately.
    assert!(
        evaluate_merge_group_tcb(
            &config_path,
            &cfg,
            &[&s0_tree, &pre_onboard_tree],
            &[t0, t1],
            &[t0],
            &onboard_entries,
            &replayer_onboard,
            &|_| Ok(Vec::new()),
        )
        .is_err(),
        "deleting ci/checks.toml in merge_group must fail closed"
    );
}

// ---------------------------------------------------------------------------
// 4. Compile-Time-Offline `evaluate_gate`: Dual Config, All 7 Clauses,
//    Attempt Resolution, Shadow Mode, Fork Slug Parity & Closure Confinement
// ---------------------------------------------------------------------------

#[test]
fn evaluate_gate_enforces_all_seven_clauses_dual_config_and_attempt_resolution() {
    let live_toml = minimal_checks_toml("");
    // Candidate PR adds a brand-new check `lint` to `[[checks]]` (owner-approved edit).
    let target_toml = minimal_checks_toml(
        r#"
[[checks]]
id = "lint"
image = "base"
runner = "ubuntu-24.04"
inputs = [{ kind = "glob", include = ["src/**"] }]
command = ["cargo", "clippy"]
"#,
    );
    let config_path = RepoRelPath::new("ci/checks.toml").unwrap();
    let live_cfg = ChecksConfig::parse_toml(&live_toml, &config_path).unwrap();
    let target_cfg = ChecksConfig::parse_toml(&target_toml, &config_path).unwrap();
    let live_sha = Sha256Digest::hash_bytes(live_toml.as_bytes());
    let target_sha = Sha256Digest::hash_bytes(target_toml.as_bytes());

    let target_tree = minimal_repo_tree(&target_toml);
    let validated = validate_config_against_tree(&target_cfg, &target_tree).unwrap();

    let img_id = ImageId::new("base").unwrap();
    let df_bytes = target_tree
        .read_blob(&RepoRelPath::new("ci/docker/base.Dockerfile").unwrap())
        .unwrap();
    let recipe_preimage = ImageRecipePreimage::new(
        RepoRelPath::new("ci/docker/base.Dockerfile").unwrap(),
        Sha256Digest::hash_bytes(&df_bytes),
        validated.image_closures[&img_id].merkle_digest(),
        BTreeMap::new(),
        BTreeMap::new(),
        Platform::LinuxAmd64,
        target_cfg.repo.slug.source_repo_url(),
    );
    let recipe = recipe_preimage.digest();
    let img_manifest = Sha256Digest::hash_bytes(b"manifest-base-v1");

    let mut scheduled_checks = BTreeMap::new();
    for cid_s in ["unit", "lint"] {
        let cid = CheckId::new(cid_s).unwrap();
        let cspec = target_cfg.check(&cid).unwrap();
        let pre = ActionPreimage {
            check_id: cid.clone(),
            source_merkle: validated.check_closures[&cid].merkle_digest(),
            platform: Platform::LinuxAmd64,
            sandbox: SandboxMode::Container,
            writable_dirs: Vec::new(),
            workdir: None,
            command: cspec.command.as_slice().to_vec(),
            env: BTreeMap::new(),
            pins: BTreeMap::new(),
            cache_mounts: Vec::<CacheMountBinding>::new(),
            declared_outputs: Vec::<OutputName>::new(),
        };
        scheduled_checks.insert(
            cid.clone(),
            ScheduledCheckPlan {
                check_id: cid,
                image_id: img_id.clone(),
                runner: "ubuntu-24.04".to_owned(),
                sandbox: SandboxMode::Container,
                shard_group: None,
                action_preimage: pre,
                caches: BTreeMap::new(),
            },
        );
    }

    let mut images = BTreeMap::new();
    images.insert(
        img_id.clone(),
        ImagePlan::PendingBuild {
            recipe,
            preimage: recipe_preimage.clone(),
            runner: "ubuntu-24.04".to_owned(),
            platform: Platform::LinuxAmd64,
        },
    );
    let shards = pack_execute_shards(&scheduled_checks, &images).unwrap();

    let pr_head = oid(C1);
    let ev_sha = oid(C2);
    let plan = ExecutionPlan {
        plan_attempt: 1,
        evaluated_at: UnixSecs(10_000),
        mode: RunMode::Enforce,
        event: TriggerEvent::PullRequest,
        runtime_ref: "refs/pull/7/merge".to_owned(),
        pr_base_ref: Some("main".to_owned()),
        event_sha: ev_sha,
        second_parent: Some(pr_head),
        publish_eligible: false,
        needs_publish: false,
        base_cfg_sha256: live_sha,
        candidate_cfg_sha256: target_sha,
        merge_group_chain_trees: None,
        tcb: TcbPlan::RequiresOwnerApproval {
            required_prs: NonEmptyVec::singleton((7, pr_head)),
            control_plane_transition: None,
        },
        images,
        pending_images: vec![PendingImageBuild {
            recipe,
            image_ids: NonEmptyVec::singleton(img_id),
            runner: "ubuntu-24.04".to_owned(),
            platform: Platform::LinuxAmd64,
            preimage: recipe_preimage,
        }],
        reused_checks: BTreeMap::new(),
        scheduled_checks: scheduled_checks.clone(),
        shards,
    };
    let plan_bytes = serde_json::to_vec(&plan).unwrap();
    let plan_sha = Sha256Digest::hash_bytes(&plan_bytes);

    // Attempt Resolution Rule: attempt 2 overrides attempt 1; stale plan_sha is ignored!
    let img_records = vec![
        BuiltImageMeta {
            plan_sha256: Sha256Digest::hash_bytes(b"other-plan"),
            attempt: 3,
            recipe,
            manifest: Sha256Digest::hash_bytes(b"bad"),
            verified_config_digest: Sha256Digest::hash_bytes(b"cfg"),
        },
        BuiltImageMeta {
            plan_sha256: plan_sha,
            attempt: 1,
            recipe,
            manifest: Sha256Digest::hash_bytes(b"old"),
            verified_config_digest: Sha256Digest::hash_bytes(b"cfg"),
        },
        BuiltImageMeta {
            plan_sha256: plan_sha,
            attempt: 2,
            recipe,
            manifest: img_manifest,
            verified_config_digest: Sha256Digest::hash_bytes(b"cfg2"),
        },
    ];
    let built_images = resolve_attempt_records(&img_records, &plan_sha, 1, 2).unwrap();
    assert_eq!(built_images[&recipe].manifest, img_manifest);

    let mut shard_outcomes = BTreeMap::new();
    for sh in &plan.shards {
        let mut outcomes = Vec::new();
        for cid in sh.checks.iter() {
            let splan = &scheduled_checks[cid];
            outcomes.push(CheckExecutionOutcome {
                check_id: cid.clone(),
                status: CheckExecStatus::Passed,
                action: splan.action_preimage.finalize(&img_manifest),
                outputs: BTreeMap::new(),
                hydrated_caches: Vec::new(),
                staged_caches: Vec::new(),
            });
        }
        shard_outcomes.insert(
            sh.shard_index,
            ShardMeta {
                plan_sha256: plan_sha,
                attempt: 2,
                shard_index: sh.shard_index,
                outcomes,
                bundles: BTreeMap::new(),
            },
        );
    }

    let observed_run = WorkflowRunMeta {
        path: ".github/workflows/ci.yml".to_owned(),
        workflow_id: 55,
        is_org_required_workflow: WorkflowRunMeta::parse_is_org_required_workflow(
            "https://api.github.com/repos/google/demo/actions/workflows/55",
            55,
        )
        .unwrap(),
        referenced_workflows: vec![ReferencedWorkflow {
            path: format!("joshlf/ci-core/.github/workflows/ci.yml@{S1}"),
            sha: oid(S1),
            ref_str: None,
        }],
    };
    let jobs = ObservedJobResults {
        plan: UpstreamJobResult::Success,
        build_images: UpstreamJobResult::Success,
        execute: UpstreamJobResult::Success,
        publish: UpstreamJobResult::Skipped,
    };
    let mut approvals = BTreeMap::new();
    approvals.insert(
        7,
        vec![PrReview {
            review_id: 1,
            user_id: 10,
            state: PrReviewState::Approved,
            commit_id: Some(pr_head),
            body: String::new(),
            submitted_at: UnixSecs(10_010),
        }],
    );

    // 1. Dual-config happy path: `target_cfg` has `[unit, lint]` while `live_cfg` has `[unit]`;
    // `evaluate_gate` accepts without Check-Set Edit Deadlock!
    let pass = evaluate_gate(
        EvalStage::FinalGate,
        false,
        UnixSecs(10_100),
        "Google/Demo", // mixed-case runtime slug accepted case-insensitively
        100,
        TriggerEvent::PullRequest,
        "refs/pull/7/merge",
        Some("main"),
        ev_sha,
        Some(pr_head),
        Some(live_sha),
        false,
        false,
        false,
        &live_cfg,
        &target_cfg,
        target_sha,
        Ok(()),
        Ok(()),
        Ok(()),
        &[],
        &[],
        true,
        &observed_run,
        jobs,
        &plan_bytes,
        plan_sha,
        &plan,
        &approvals,
        &built_images,
        &shard_outcomes,
        &BTreeMap::new(),
    )
    .expect("valid dual-config PR gate must pass");
    assert_eq!(pass, GatePass::Enforced);

    // 2. Reject workflow cancellation (`workflow_cancelled == true`).
    assert_eq!(
        evaluate_gate(
            EvalStage::FinalGate,
            true,
            UnixSecs(10_100),
            "google/demo",
            100,
            TriggerEvent::PullRequest,
            "refs/pull/7/merge",
            Some("main"),
            ev_sha,
            Some(pr_head),
            Some(live_sha),
            false,
            false,
            false,
            &live_cfg,
            &target_cfg,
            target_sha,
            Ok(()),
            Ok(()),
            Ok(()),
            &[],
            &[],
            true,
            &observed_run,
            jobs,
            &plan_bytes,
            plan_sha,
            &plan,
            &approvals,
            &built_images,
            &shard_outcomes,
            &BTreeMap::new(),
        ),
        Err(GateError::Cancelled)
    );

    // 3. Reject TTL expiry (`eval_now - plan.evaluated_at > 21_600`).
    assert!(
        evaluate_gate(
            EvalStage::FinalGate,
            false,
            UnixSecs(10_000 + 21_601),
            "google/demo",
            100,
            TriggerEvent::PullRequest,
            "refs/pull/7/merge",
            Some("main"),
            ev_sha,
            Some(pr_head),
            Some(live_sha),
            false,
            false,
            false,
            &live_cfg,
            &target_cfg,
            target_sha,
            Ok(()),
            Ok(()),
            Ok(()),
            &[],
            &[],
            true,
            &observed_run,
            jobs,
            &plan_bytes,
            plan_sha,
            &plan,
            &approvals,
            &built_images,
            &shard_outcomes,
            &BTreeMap::new(),
        )
        .is_err()
    );

    // 4. Reject missing owner approval in Clause 2.
    assert!(
        evaluate_gate(
            EvalStage::FinalGate,
            false,
            UnixSecs(10_100),
            "google/demo",
            100,
            TriggerEvent::PullRequest,
            "refs/pull/7/merge",
            Some("main"),
            ev_sha,
            Some(pr_head),
            Some(live_sha),
            false,
            false,
            false,
            &live_cfg,
            &target_cfg,
            target_sha,
            Ok(()),
            Ok(()),
            Ok(()),
            &[],
            &[],
            true,
            &observed_run,
            jobs,
            &plan_bytes,
            plan_sha,
            &plan,
            &BTreeMap::new(),
            &built_images,
            &shard_outcomes,
            &BTreeMap::new(),
        )
        .is_err()
    );

    // 5. Verify `OrgRuleset` `workflow_url` distinction (`/actions/required_workflows/{id}`)
    // and `verify_engine_workflows` `@main` + dual-SHA rejection!
    assert!(
        WorkflowRunMeta::parse_is_org_required_workflow(
            "https://api.github.com/repos/google/demo/actions/required_workflows/99",
            99,
        )
        .unwrap()
    );
    let dual_refs = vec![
        ReferencedWorkflow {
            path: format!("joshlf/ci-core/.github/workflows/ci.yml@{S1}"),
            sha: oid(S1),
            ref_str: None,
        },
        ReferencedWorkflow {
            path: format!("joshlf/ci-core/.github/workflows/ci.yml@{S2}"),
            sha: oid(S2),
            ref_str: None,
        },
    ];
    let mut two_sha_pol = live_cfg.repo.signer_policy().unwrap();
    two_sha_pol.trusted_engine_shas = NonEmptyVec::new(vec![oid(S1), oid(S2)]).unwrap();
    assert!(
        verify_engine_workflows(&dual_refs, &two_sha_pol, TriggerEvent::PullRequest).is_err(),
        "mixing two distinct engine SHAs in a single run must fail closed"
    );

    // 5b. Verify `trusted_pr_workflow` (`ci-pr.yml`) is accepted strictly on
    // `TriggerEvent::PullRequest` and rejected on `MergeGroup` and `Push`.
    let pr_wf_refs = vec![ReferencedWorkflow {
        path: format!("joshlf/ci-core/.github/workflows/ci-pr.yml@{S1}"),
        sha: oid(S1),
        ref_str: None,
    }];
    assert_eq!(
        verify_engine_workflows(&pr_wf_refs, &two_sha_pol, TriggerEvent::PullRequest).unwrap(),
        oid(S1)
    );
    assert!(
        verify_engine_workflows(&pr_wf_refs, &two_sha_pol, TriggerEvent::MergeGroup).is_err(),
        "ci-pr.yml must be rejected on MergeGroup"
    );
    assert!(
        verify_engine_workflows(&pr_wf_refs, &two_sha_pol, TriggerEvent::Push).is_err(),
        "ci-pr.yml must be rejected on Push"
    );

    // 5c. Verify `[commit_policy] forbid_message_regex` and `shard_group` co-location.
    let cp_toml = minimal_checks_toml(
        r#"
[commit_policy]
forbid_message_regex = '\bT[O]DO\b'

[[checks]]
id = "fast-a"
image = "base"
runner = "ubuntu-24.04"
shard_group = "fast-scripts"
inputs = [{ kind = "glob", include = ["src/**"] }]
command = ["cargo", "check"]

[[checks]]
id = "fast-b"
image = "base"
runner = "ubuntu-24.04"
shard_group = "fast-scripts"
inputs = [{ kind = "glob", include = ["src/**"] }]
command = ["cargo", "fmt", "--check"]
"#,
    );
    let cp_cfg = ChecksConfig::parse_toml(&cp_toml, &config_path).unwrap();
    assert!(
        cp_cfg
            .validate_commit_messages(&[(oid(C1), "[zc] Clean commit body\n".to_owned())])
            .is_ok()
    );
    assert!(
        cp_cfg
            .validate_commit_messages(&[(
                oid(C1),
                format!("[zc] Draft commit\n\n{} fix later\n", "TODO:")
            )])
            .is_err(),
        "commit_policy.forbid_message_regex must reject forbidden marker in commit message"
    );
    // Reject `commit_policy_ok == Err(...)` in `evaluate_gate` Clause 1.
    assert!(
        evaluate_gate(
            EvalStage::FinalGate,
            false,
            UnixSecs(10_100),
            "google/demo",
            100,
            TriggerEvent::PullRequest,
            "refs/pull/7/merge",
            Some("main"),
            ev_sha,
            Some(pr_head),
            Some(live_sha),
            false,
            false,
            false,
            &live_cfg,
            &target_cfg,
            target_sha,
            Ok(()),
            Ok(()),
            Err("forbidden marker in commit".to_owned()),
            &[],
            &[],
            true,
            &observed_run,
            jobs,
            &plan_bytes,
            plan_sha,
            &plan,
            &approvals,
            &built_images,
            &shard_outcomes,
            &BTreeMap::new(),
        )
        .is_err()
    );

    let mut sg_sched = scheduled_checks.clone();
    for fast_id in ["fast-a", "fast-b"] {
        let fcid = CheckId::new(fast_id).unwrap();
        let fspec = cp_cfg.check(&fcid).unwrap();
        let mut fpre = scheduled_checks[&CheckId::new("unit").unwrap()]
            .action_preimage
            .clone();
        fpre.check_id = fcid.clone();
        sg_sched.insert(
            fcid.clone(),
            ScheduledCheckPlan {
                check_id: fcid,
                image_id: ImageId::new("base").unwrap(),
                runner: "ubuntu-24.04".to_owned(),
                sandbox: SandboxMode::Container,
                shard_group: fspec.shard_group.clone(),
                action_preimage: fpre,
                caches: BTreeMap::new(),
            },
        );
    }
    let sg_shards = pack_execute_shards(&sg_sched, &plan.images).unwrap();
    // `fast-a` and `fast-b` share `shard_group = "fast-scripts"` -> 1 shard;
    // `lint` and `unit` have `shard_group = None` -> 2 dedicated shards = 3 total!
    assert_eq!(sg_shards.len(), 3);
    assert!(
        sg_shards.iter().any(|s| s.checks.len() == 2
            && s.checks.contains(&CheckId::new("fast-a").unwrap())
            && s.checks.contains(&CheckId::new("fast-b").unwrap())),
        "checks sharing shard_group must co-locate in a single shard"
    );

    // 6. Verify `decide_review_rerun` across `DataPin` partial vs full TTL threshold (`21,000s`).
    let gate_only_fail_jobs = CompletedRunJobs {
        plan: UpstreamJobResult::Success,
        build_images: UpstreamJobResult::Success,
        execute: UpstreamJobResult::Success,
        gate: UpstreamJobResult::Failure,
    };
    assert_eq!(
        decide_review_rerun(
            true,
            true,
            true,
            gate_only_fail_jobs,
            Some(&plan),
            Some(true),
            UnixSecs(10_000 + 21_000),
        ),
        ReviewRerunDecision::RerunFailedJobs
    );
    assert_eq!(
        decide_review_rerun(
            true,
            true,
            true,
            gate_only_fail_jobs,
            Some(&plan),
            Some(true),
            UnixSecs(10_000 + 21_001),
        ),
        ReviewRerunDecision::RerunFull
    );

    // 7. Verify `evaluate_pr_tcb` schedules check execution for unapproved ExecutableTcb PRs
    // when running under `live_cfg`'s caller/engine (`RequiresOwnerApproval` with
    // `control_plane_transition: None` so `execute` verifies the PR before `gate` holds for
    // owner approval, and `rerun-failed-jobs` re-evaluates `gate` alone once approved),
    // blocks upfront (`TcbPlan::Blocked`) when an unapproved PR modifies caller/engine
    // pinning (`caller_or_engine_blocked_under_live == true`), handles pre-onboarding
    // `base_tree` + `ShadowPrPlanOnly` (`live_shadow_pr_authorized`), and supports stacked
    // PRs (`base_ref != default_branch`) in `evaluate_gate`.
    let base_tree = minimal_repo_tree(&live_toml);
    let unapproved_exec = evaluate_pr_tcb(
        &RepoRelPath::new("ci/checks.toml").unwrap(),
        &live_cfg,
        &live_cfg,
        &target_cfg,
        &base_tree,
        &target_tree,
        7,
        pr_head,
        &[],
        false,
    )
    .unwrap();
    assert_eq!(
        unapproved_exec,
        TcbPlan::RequiresOwnerApproval {
            required_prs: ci_core_model::types::NonEmptyVec::singleton((7, pr_head)),
            control_plane_transition: None,
        }
    );
    let blocked = evaluate_pr_tcb(
        &RepoRelPath::new("ci/checks.toml").unwrap(),
        &live_cfg,
        &live_cfg,
        &target_cfg,
        &base_tree,
        &target_tree,
        7,
        pr_head,
        &[],
        true,
    )
    .unwrap();
    assert!(matches!(blocked, TcbPlan::Blocked { .. }));

    let mut pre_onboard_base = InMemoryTree::new();
    pre_onboard_base.insert_file("src/lib.rs", b"pub fn pre() {}\n".to_vec());
    let pre_onboard_unapproved = evaluate_pr_tcb(
        &RepoRelPath::new("ci/checks.toml").unwrap(),
        &target_cfg,
        &target_cfg,
        &target_cfg,
        &pre_onboard_base,
        &target_tree,
        7,
        pr_head,
        &[],
        false,
    )
    .unwrap();
    assert!(matches!(
        pre_onboard_unapproved,
        TcbPlan::RequiresOwnerApproval { .. }
    ));
    let pre_onboard_approved = evaluate_pr_tcb(
        &RepoRelPath::new("ci/checks.toml").unwrap(),
        &target_cfg,
        &target_cfg,
        &target_cfg,
        &pre_onboard_base,
        &target_tree,
        7,
        pr_head,
        &approvals[&7],
        false,
    )
    .unwrap();
    assert!(matches!(
        pre_onboard_approved,
        TcbPlan::RequiresOwnerApproval { .. }
    ));

    // Verify `ShadowPrPlanOnly` passes without owner approval when `live_shadow_pr_authorized == true`
    // (pre-onboarding or `live_tree` already sets `shadow_mode: true`), AND fails closed in Clause 2
    // when `live_shadow_pr_authorized == false` (blocking unapproved `shadow_mode: false -> true` downgrades!).
    let mut shadow_plan = plan.clone();
    shadow_plan.mode = ci_core_model::types::RunMode::ShadowPrPlanOnly;
    shadow_plan.pending_images.clear();
    shadow_plan.shards.clear();
    let shadow_bytes = serde_json::to_vec(&shadow_plan).unwrap();
    let shadow_sha = Sha256Digest::hash_bytes(&shadow_bytes);
    let shadow_jobs = ObservedJobResults {
        plan: UpstreamJobResult::Success,
        build_images: UpstreamJobResult::Skipped,
        execute: UpstreamJobResult::Skipped,
        publish: UpstreamJobResult::Skipped,
    };
    let empty_revs: BTreeMap<u64, Vec<ci_core_model::store::PrReview>> =
        BTreeMap::from([(7, Vec::new())]);
    assert_eq!(
        evaluate_gate(
            EvalStage::FinalGate,
            false,
            UnixSecs(10_100),
            "google/demo",
            100,
            TriggerEvent::PullRequest,
            "refs/pull/7/merge",
            Some("main"),
            ev_sha,
            Some(pr_head),
            Some(live_sha),
            true,
            true,
            false,
            &live_cfg,
            &target_cfg,
            target_sha,
            Ok(()),
            Ok(()),
            Ok(()),
            &[],
            &[],
            true,
            &observed_run,
            shadow_jobs,
            &shadow_bytes,
            shadow_sha,
            &shadow_plan,
            &empty_revs,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .expect("authorized shadow bring-up PR must pass ShadowPlanVerified"),
        GatePass::ShadowPlanVerified
    );
    assert!(
        evaluate_gate(
            EvalStage::FinalGate,
            false,
            UnixSecs(10_100),
            "google/demo",
            100,
            TriggerEvent::PullRequest,
            "refs/pull/7/merge",
            Some("main"),
            ev_sha,
            Some(pr_head),
            Some(live_sha),
            true,
            false,
            false,
            &live_cfg,
            &target_cfg,
            target_sha,
            Ok(()),
            Ok(()),
            Ok(()),
            &[],
            &[],
            true,
            &observed_run,
            shadow_jobs,
            &shadow_bytes,
            shadow_sha,
            &shadow_plan,
            &empty_revs,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .is_err(),
        "unapproved shadow_mode downgrade after cutover must fail closed in Clause 2"
    );

    // Stacked PR (`base_ref == Some("stack-base-01")`) passes `evaluate_gate` when bound to `plan.pr_base_ref`,
    // and rejects empty/malformed `base_ref` (`Some("")`, `Some("../evil")`, `None`).
    let mut stacked_plan = plan.clone();
    stacked_plan.pr_base_ref = Some("stack-base-01".to_owned());
    stacked_plan.base_cfg_sha256 = Sha256Digest::hash_bytes(&[]);
    let stacked_bytes = serde_json::to_vec(&stacked_plan).unwrap();
    let stacked_sha = Sha256Digest::hash_bytes(&stacked_bytes);
    let mut stacked_imgs = built_images.clone();
    for m in stacked_imgs.values_mut() {
        m.plan_sha256 = stacked_sha;
    }
    let mut stacked_shards = shard_outcomes.clone();
    for s in stacked_shards.values_mut() {
        s.plan_sha256 = stacked_sha;
    }
    assert_eq!(
        evaluate_gate(
            EvalStage::FinalGate,
            false,
            UnixSecs(10_100),
            "google/demo",
            100,
            TriggerEvent::PullRequest,
            "refs/pull/7/merge",
            Some("stack-base-01"),
            ev_sha,
            Some(pr_head),
            Some(Sha256Digest::hash_bytes(&[])),
            false,
            false,
            false,
            &target_cfg,
            &target_cfg,
            target_sha,
            Ok(()),
            Ok(()),
            Ok(()),
            &[],
            &[],
            true,
            &observed_run,
            jobs,
            &stacked_bytes,
            stacked_sha,
            &stacked_plan,
            &approvals,
            &stacked_imgs,
            &stacked_shards,
            &BTreeMap::new(),
        )
        .expect("stacked onboarding PR gate must pass when owner-approved"),
        GatePass::Enforced
    );
    for bad_base in [None, Some(""), Some("../main"), Some("-flag")] {
        let mut bad_plan = stacked_plan.clone();
        bad_plan.pr_base_ref = bad_base.map(str::to_owned);
        let bad_bytes = serde_json::to_vec(&bad_plan).unwrap();
        let bad_sha = Sha256Digest::hash_bytes(&bad_bytes);
        assert!(
            evaluate_gate(
                EvalStage::FinalGate,
                false,
                UnixSecs(10_100),
                "google/demo",
                100,
                TriggerEvent::PullRequest,
                "refs/pull/7/merge",
                bad_base,
                ev_sha,
                Some(pr_head),
                Some(Sha256Digest::hash_bytes(&[])),
                false,
                false,
                false,
                &target_cfg,
                &target_cfg,
                target_sha,
                Ok(()),
                Ok(()),
                Ok(()),
                &[],
                &[],
                true,
                &observed_run,
                jobs,
                &bad_bytes,
                bad_sha,
                &bad_plan,
                &approvals,
                &stacked_imgs,
                &stacked_shards,
                &BTreeMap::new(),
            )
            .is_err(),
            "malformed PR base_ref {bad_base:?} must fail closed"
        );
    }

    // 8. Verify multi-hop symlink confinement (`validate_source_closure` & `validate_confined_dir`).
    let mut esc_tree = minimal_repo_tree(&live_toml);
    esc_tree.insert_symlink("src/link.rs", "../ci/checks.toml");
    let closure: BTreeSet<RepoRelPath> = [
        RepoRelPath::new("src/lib.rs").unwrap(),
        RepoRelPath::new("src/link.rs").unwrap(),
    ]
    .into_iter()
    .collect();
    assert!(
        validate_source_closure(&esc_tree, &closure, None, &[]).is_err(),
        "symlink escaping declared closure must fail closed before TreeMerkle"
    );

    // Multi-hop confined-dir escape: `x/y -> ..` (inside root) + `z -> x/y/..` (escapes root!).
    let mut dir_entries = BTreeMap::new();
    dir_entries.insert(
        RepoRelPath::new("x/y").unwrap(),
        ConfinedEntry::Symlink {
            target: "..".to_owned(),
        },
    );
    dir_entries.insert(
        RepoRelPath::new("z").unwrap(),
        ConfinedEntry::Symlink {
            target: "x/y/..".to_owned(),
        },
    );
    assert!(
        validate_confined_dir(&dir_entries).is_err(),
        "two-hop relative symlink chain escaping cache root must fail closed"
    );

    let _ = (
        AbsUnixPath::new("/cargo-home").unwrap(),
        RepoSlug::new("Google/ZeroCopy").unwrap(),
        ControlPlaneTransition::new(live_cfg.control_plane(), target_cfg.control_plane()),
        caller_allowed_effective,
    );
}

#[test]
fn canonical_tree_validated_preimages_and_branch_identity_invariants() {
    use ci_core_model::config::validate_config_against_tree;
    use ci_core_model::types::{ImageId, is_valid_git_branch_name};

    assert!(is_valid_git_branch_name("main"));
    assert!(is_valid_git_branch_name("feature/stack-01"));
    for bad in ["", "-flag", "/lead", "trail/", "a..b", "a//b", "sp ace"] {
        assert!(!is_valid_git_branch_name(bad), "{bad:?} must be rejected");
    }

    let toml_str = minimal_checks_toml("");
    let bad_branch_toml =
        toml_str.replace("default_branch = \"main\"", "default_branch = \"-bad\"");
    let config_path = RepoRelPath::new("ci/checks.toml").unwrap();
    assert!(
        ChecksConfig::parse_toml(&bad_branch_toml, &config_path).is_err(),
        "default_branch starting with '-' must fail closed"
    );

    let cfg = ChecksConfig::parse_toml(&toml_str, &config_path).unwrap();
    assert!(cfg.repo.same_identity(&cfg.repo));
    let mut other_cfg = cfg.clone();
    other_cfg.repo.id += 1;
    assert!(!cfg.repo.same_identity(&other_cfg.repo));

    let tree = minimal_repo_tree(&toml_str);
    let validated = validate_config_against_tree(&cfg, &tree).unwrap();
    let img_id = ImageId::new("base").unwrap();
    assert!(validated.dockerfile_digests.contains_key(&img_id));
    let recipe_pre = validated.image_recipe_preimage(&cfg, &img_id).unwrap();
    assert_eq!(
        recipe_pre.dockerfile_sha256,
        validated.dockerfile_digests[&img_id]
    );
    let projected = recipe_pre.projected_build_args();
    assert!(projected.is_empty());

    let chk_id = CheckId::new("unit").unwrap();
    let action_pre = validated.action_preimage(&cfg, &chk_id).unwrap();
    assert_eq!(action_pre.check_id, chk_id);
}
