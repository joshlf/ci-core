//! Compile-time purity firewall (`trybuild` + `cargo tree`) and serde
//! representation-invariant enforcement tests for `ci-core-model`.

use std::process::Command;

use ci_core_model::types::{
    CallerMode, CodeOwnerPrincipal, ControlPlanePolicy, ControlPlaneTransition, GitOid,
    NonEmptyVec, RepoRelPath, RepoSlug, SignerPolicy, SigstoreRoot, WorkflowUri,
};

#[test]
fn trybuild_opaque_proof_and_invariant_types_fail_to_compile_when_bypassed() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}

#[test]
fn ci_core_model_normal_dependency_tree_contains_zero_io_http_or_async_crates() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let out = Command::new("cargo")
        .args(["tree", "-p", "ci-core-model", "--edges", "normal"])
        .current_dir(manifest_dir)
        .output()
        .expect("failed to run cargo tree");
    assert!(out.status.success(), "cargo tree failed");
    let tree = String::from_utf8(out.stdout).unwrap();
    for forbidden in [
        "reqwest",
        "hyper",
        "tokio",
        "rustix",
        "sigstore-sign",
        "sigstore-fulcio",
        "sigstore-oidc",
        "sigstore-tuf",
        "tempfile",
        "tar ",
    ] {
        assert!(
            !tree.contains(forbidden),
            "ci-core-model normal dependency tree must not depend on `{forbidden}`:\n{tree}"
        );
    }
}

#[test]
fn serde_deserialization_enforces_non_empty_vec_repo_slug_and_nontrivial_transition() {
    // 1. `NonEmptyVec` rejects empty JSON array `[]`.
    let empty_res: Result<NonEmptyVec<u64>, _> = serde_json::from_str("[]");
    assert!(empty_res.is_err(), "NonEmptyVec must reject empty `[]`");

    // 2. `RepoSlug` derives lowercased `oci_path` on Deserialize.
    let slug: RepoSlug = serde_json::from_str("\"Google/ZeroCopy\"").unwrap();
    assert_eq!(slug.canonical(), "Google/ZeroCopy");
    assert_eq!(slug.oci_path(), "google/zerocopy");

    // 3. `ControlPlaneTransition` rejects `base == candidate` on both construction and Deserialize.
    let cp = ControlPlanePolicy {
        signer: SignerPolicy {
            repo_id: 1,
            owner_id: 2,
            default_branch: "main".to_owned(),
            oidc_issuer: "https://token.actions.githubusercontent.com".to_owned(),
            sigstore: SigstoreRoot::PublicGood,
            trusted_engine_workflow: WorkflowUri::new("org/ci-core/.github/workflows/ci.yml")
                .unwrap(),
            trusted_pr_workflow: WorkflowUri::new("org/ci-core/.github/workflows/ci-pr.yml")
                .unwrap(),
            trusted_review_signal_workflow: WorkflowUri::new(
                "org/ci-core/.github/workflows/review-signal.yml",
            )
            .unwrap(),
            trusted_review_rerun_workflow: WorkflowUri::new(
                "org/ci-core/.github/workflows/review-rerun.yml",
            )
            .unwrap(),
            trusted_engine_shas: NonEmptyVec::singleton(
                GitOid::from_hex("1111111111111111111111111111111111111111").unwrap(),
            ),
        },
        caller: CallerMode::RepoRuleset {
            caller_workflows: NonEmptyVec::singleton(
                RepoRelPath::new(".github/workflows/ci.yml").unwrap(),
            ),
            gate_check_name: "ci / gate".to_owned(),
            codeowners: NonEmptyVec::singleton(CodeOwnerPrincipal::new("@owner").unwrap()),
        },
    };
    assert_eq!(ControlPlaneTransition::new(cp.clone(), cp.clone()), None);
    let trivial_json = serde_json::json!({ "base": cp, "candidate": cp });
    let deser: Result<ControlPlaneTransition, _> = serde_json::from_value(trivial_json);
    assert!(
        deser.is_err(),
        "ControlPlaneTransition must reject base == candidate on Deserialize"
    );
}
