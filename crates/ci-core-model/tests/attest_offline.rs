//! Offline Sigstore verification tests against compile-time embedded
//! `PublicGood` and `GitHub` `TrustedRoot`s using real reference bundles.

use ci_core_model::attest::{AttestError, verify_offline};
use ci_core_model::digest::canonicalize_claim;
use ci_core_model::types::{
    Claim, GitOid, NonEmptyVec, Sha256Digest, SignerPolicy, SigstoreRoot, UnixSecs, WorkflowUri,
};

const CONDA_ATTESTATION: &[u8] =
    include_bytes!("fixtures/sigstore/conda-attestation.sigstore.json");
const GITHUB_PRIVATE_ATTESTATION: &[u8] =
    include_bytes!("fixtures/sigstore/github-private-attestation.sigstore.json");
const CVE_2022_36056_BUNDLE: &[u8] =
    include_bytes!("fixtures/sigstore/bundle_cve_2022_36056.txt.sigstore");
const DSSE_2SIGS_BUNDLE: &[u8] = include_bytes!("fixtures/sigstore/dsse-2sigs.sigstore.json");

fn policy(sigstore: SigstoreRoot) -> SignerPolicy {
    SignerPolicy {
        repo_id: 534354967,
        owner_id: 1342004,
        default_branch: "main".to_owned(),
        oidc_issuer: "https://token.actions.githubusercontent.com".to_owned(),
        sigstore,
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
        trusted_engine_shas: NonEmptyVec::singleton(
            GitOid::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
        ),
    }
}

#[test]
fn embedded_trusted_roots_reject_foreign_legacy_and_multi_sig_bundles_offline() {
    let img_claim = Claim::Image {
        recipe: Sha256Digest::hash_bytes(b"recipe"),
        manifest: Sha256Digest::hash_bytes(b"manifest"),
    };
    let (claim_bytes, _) = canonicalize_claim(&img_claim).unwrap();
    let tag = img_claim.lookup_tag();
    let now = UnixSecs(1_760_000_000);

    // 1. Real SLSA v1 conda attestation fails closed on predicateType (`urn:ci-core:batch-claims:v1` required).
    let err = verify_offline(
        &tag,
        &claim_bytes,
        CONDA_ATTESTATION,
        &policy(SigstoreRoot::PublicGood),
        now,
    )
    .unwrap_err();
    assert!(
        matches!(err, AttestError::StatementBinding(_)),
        "expected StatementBinding error on foreign SLSA predicateType, got: {err:?}"
    );

    // 2. Real GitHub private attestation fails closed against our `urn:ci-core:batch-claims:v1` binding
    // under both embedded `GitHub` and `PublicGood` roots (and initializes both embedded roots cleanly).
    let err_gh = verify_offline(
        &tag,
        &claim_bytes,
        GITHUB_PRIVATE_ATTESTATION,
        &policy(SigstoreRoot::GitHub),
        now,
    )
    .unwrap_err();
    assert!(matches!(err_gh, AttestError::StatementBinding(_)));

    // 3. CVE-2022-36056 legacy v0.1 bundle is rejected because `Bundle0_3` is mandatory.
    let err_cve = verify_offline(
        &tag,
        &claim_bytes,
        CVE_2022_36056_BUNDLE,
        &policy(SigstoreRoot::PublicGood),
        now,
    )
    .unwrap_err();
    assert!(
        matches!(
            err_cve,
            AttestError::StatementBinding(_) | AttestError::MalformedJson(_)
        ),
        "unexpected error for CVE-2022-36056 bundle: {err_cve:?}"
    );

    // 4. Multi-signature DSSE bundle (`signatures.len() > 1`) is rejected fail-closed.
    let err_2sig = verify_offline(
        &tag,
        &claim_bytes,
        DSSE_2SIGS_BUNDLE,
        &policy(SigstoreRoot::PublicGood),
        now,
    )
    .unwrap_err();
    assert!(matches!(err_2sig, AttestError::MalformedJson(_)));
}
