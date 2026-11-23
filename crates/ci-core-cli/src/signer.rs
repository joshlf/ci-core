//! Online batch keyless DSSE signing (`sigstore-sign@0.16.0`, `publish` ONLY,
//! `0` GitHub Attestations API calls) and bottom-up Claim commit ordering
//! (`isha256` -> `ksha256` -> `asha256`, strictly after `msha256` image push).

use base64::Engine as _;
use ci_core_model::attest::BATCH_CLAIMS_PREDICATE_TYPE;
use ci_core_model::digest::canonicalize_claim;
use ci_core_model::store::{BlobDescriptor, BlobRef, Registry, StoreError, StoreTier};
use ci_core_model::types::{Claim, GitOid, LookupTag, Sha256Digest, SignerPolicy, SigstoreRoot};
use reqwest::blocking::Client;
use serde::Deserialize;
use sigstore_sign::oidc::IdentityToken;
use sigstore_sign::{Attestation, SigningContext, SigstoreInstance};
use sigstore_types::{MediaType, Sha256Hash};
use thiserror::Error;

/// Errors emitted during batch signing or bottom-up claim publication.
#[derive(Debug, Error)]
pub enum SignerError {
    /// Failed to request or validate the GitHub Actions OIDC JWT.
    #[error("OIDC token assertion failed: {0}")]
    Oidc(String),
    /// `sigstore-sign` Fulcio/Rekor/TSA error.
    #[error("sigstore batch signing failed: {0}")]
    Sigstore(String),
    /// Canonical JCS claim serialization error.
    #[error("claim canonicalization failed: {0}")]
    Canonicalize(String),
    /// Registry commit error.
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Deserialize)]
struct ActionsOidcResponse {
    value: String,
}

#[derive(Debug, Deserialize)]
struct GitHubOidcJwtClaims {
    job_workflow_sha: Option<String>,
    job_workflow_ref: Option<String>,
    repository_visibility: Option<String>,
}

/// Decodes and validates a GitHub Actions OIDC JWT payload **before** requesting
/// a Fulcio certificate (`§3.3` step 2):
/// 1. `job_workflow_sha` is a valid 40-hex `GitOid ∈ policy.trusted_engine_shas`.
/// 2. `job_workflow_ref == format!("{}@{}", policy.trusted_engine_workflow, job_workflow_sha)`.
/// 3. When `policy.sigstore == SigstoreRoot::PublicGood`, asserts
///    `repository_visibility == "public"`.
pub fn validate_actions_oidc_jwt_claims(
    raw_jwt: &str,
    policy: &SignerPolicy,
) -> Result<GitOid, SignerError> {
    let parts: Vec<&str> = raw_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(SignerError::Oidc(
            "invalid JWT format (expected 3 dot-separated segments)".to_owned(),
        ));
    }
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| SignerError::Oidc(format!("JWT base64url decode failed: {e}")))?;
    let claims: GitHubOidcJwtClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| SignerError::Oidc(format!("JWT payload JSON parse failed: {e}")))?;

    let sha_str = claims
        .job_workflow_sha
        .as_deref()
        .ok_or_else(|| SignerError::Oidc("OIDC JWT missing `job_workflow_sha` claim".to_owned()))?;
    let wf_sha = GitOid::from_hex(sha_str).map_err(|_| {
        SignerError::Oidc(format!(
            "`job_workflow_sha` {sha_str:?} is not a 40-hex GitOid"
        ))
    })?;
    if !policy.trusted_engine_shas.contains(&wf_sha) {
        return Err(SignerError::Oidc(format!(
            "`job_workflow_sha` `{wf_sha}` is not in eff_cp.signer.trusted_engine_shas"
        )));
    }

    let expected_wf_ref = format!("{}@{wf_sha}", policy.trusted_engine_workflow);
    if claims.job_workflow_ref.as_deref() != Some(expected_wf_ref.as_str()) {
        return Err(SignerError::Oidc(format!(
            "`job_workflow_ref` {:?} != expected {expected_wf_ref:?}",
            claims.job_workflow_ref
        )));
    }

    if policy.sigstore == SigstoreRoot::PublicGood
        && claims.repository_visibility.as_deref() != Some("public")
    {
        return Err(SignerError::Oidc(format!(
            "SigstoreRoot::PublicGood requires repository_visibility == \"public\", got {:?}",
            claims.repository_visibility
        )));
    }

    Ok(wf_sha)
}

/// Exchanges `ACTIONS_ID_TOKEN_REQUEST_URL` + `ACTIONS_ID_TOKEN_REQUEST_TOKEN`
/// for a GitHub Actions OIDC JWT with `audience=sigstore`.
pub fn request_actions_oidc_jwt() -> Result<String, SignerError> {
    let req_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
        .map_err(|_| SignerError::Oidc("ACTIONS_ID_TOKEN_REQUEST_URL is not set".to_owned()))?;
    let req_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .map_err(|_| SignerError::Oidc("ACTIONS_ID_TOKEN_REQUEST_TOKEN is not set".to_owned()))?;
    let sep = if req_url.contains('?') { '&' } else { '?' };
    let full_url = format!("{req_url}{sep}audience=sigstore");

    let client = Client::builder()
        .user_agent("ci-core/0.1.0")
        .build()
        .map_err(|e| SignerError::Oidc(e.to_string()))?;
    let resp = client
        .get(&full_url)
        .header("Authorization", format!("Bearer {req_token}"))
        .header("Accept", "application/json; api-version=2.0")
        .send()
        .map_err(|e| SignerError::Oidc(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(SignerError::Oidc(format!(
            "OIDC token endpoint returned HTTP {}",
            resp.status()
        )));
    }
    let parsed: ActionsOidcResponse = resp.json().map_err(|e| SignerError::Oidc(e.to_string()))?;
    Ok(parsed.value)
}

/// Staged claim ready for batch signing and bottom-up GHCR manifest commit.
#[derive(Debug, Clone)]
pub struct StagedClaim {
    /// Target storage tier (`PublicCas` for `Image`/`Check`, `slot.tier` for `Cache`).
    pub tier: StoreTier,
    /// 72-character GHCR lookup tag (`{i,k,a}sha256-<hex>`).
    pub tag: LookupTag,
    /// Canonical RFC 8785 JCS JSON bytes of `claim`.
    pub claim_bytes: Vec<u8>,
    /// `sha256(claim_bytes)` bound as the in-toto subject digest.
    pub claim_sha256: Sha256Digest,
    /// Pre-verified, already-uploaded payload layer descriptors (`Layers 1..k`).
    pub payload_blobs: Vec<BlobDescriptor>,
}

impl StagedClaim {
    /// Canonicalizes `claim` and constructs a `StagedClaim`.
    pub fn new(
        tier: StoreTier,
        claim: &Claim,
        payload_blobs: Vec<BlobDescriptor>,
    ) -> Result<Self, SignerError> {
        let (claim_bytes, claim_sha256) =
            canonicalize_claim(claim).map_err(SignerError::Canonicalize)?;
        Ok(Self {
            tier,
            tag: claim.lookup_tag(),
            claim_bytes,
            claim_sha256,
            payload_blobs,
        })
    }
}

/// Builds a single in-toto v1 `Attestation` (`predicateType = "urn:ci-core:batch-claims:v1"`)
/// over all staged claims (`Image`, `Cache`, and `Check`).
pub fn build_batch_attestation(claims: &[StagedClaim]) -> Attestation {
    let mut att = Attestation::new(
        BATCH_CLAIMS_PREDICATE_TYPE,
        serde_json::json!({ "schema_version": 1 }),
    );
    for sc in claims {
        att = att.add_subject(
            sc.tag.as_str(),
            Sha256Hash::new(*sc.claim_sha256.as_bytes()),
        );
    }
    att
}

/// Mints **one** keyless Sigstore `Bundle0_3` in Rust (`sigstore-sign@0.16.0`,
/// `0` GitHub Attestations API calls) over all staged claims after validating
/// the Actions OIDC JWT against `policy`.
pub fn sign_batch_claims_online(
    raw_jwt: &str,
    policy: &SignerPolicy,
    staged_claims: &[StagedClaim],
) -> Result<BlobRef, SignerError> {
    if staged_claims.is_empty() {
        return Err(SignerError::Sigstore(
            "cannot sign an empty batch of claims".to_owned(),
        ));
    }
    let _verified_wf_sha = validate_actions_oidc_jwt_claims(raw_jwt, policy)?;
    let identity_token = IdentityToken::from_jwt(raw_jwt)
        .map_err(|e| SignerError::Oidc(format!("IdentityToken::from_jwt: {e}")))?;

    let instance = match policy.sigstore {
        SigstoreRoot::PublicGood => SigstoreInstance::PublicGood,
        SigstoreRoot::GitHub => SigstoreInstance::GitHub,
    };
    let attestation = build_batch_attestation(staged_claims);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| SignerError::Sigstore(format!("tokio runtime init: {e}")))?;

    let bundle = rt.block_on(async move {
        let ctx = match SigningContext::for_instance(instance).await {
            Ok(c) => c,
            Err(_) => SigningContext::from_embedded(instance)
                .map_err(|e| SignerError::Sigstore(e.to_string()))?,
        };
        let signer = ctx.signer(identity_token);
        signer
            .sign_attestation(attestation)
            .await
            .map_err(|e| SignerError::Sigstore(e.to_string()))
    })?;

    if bundle.media_type() != MediaType::Bundle0_3 {
        return Err(SignerError::Sigstore(format!(
            "unexpected bundle mediaType {:?}",
            bundle.media_type()
        )));
    }
    let bundle_json = bundle
        .to_json()
        .map_err(|e| SignerError::Sigstore(e.to_string()))?;
    Ok(BlobRef::from_bytes(bundle_json.into_bytes()))
}

/// Commits pre-signed `StagedClaim` manifests in strict bottom-up dependency
/// order (`§3.2`):
/// 1. `Claim::Image` (`isha256-<recipe>`) — note untouched `msha256-<M>` image
///    manifests were already pushed and verified *before* signing!
/// 2. `Claim::Cache` (`ksha256-<key>`)
/// 3. `Claim::Check` (`asha256-<action>`, strictly last so an outage never
///    leaves a pass receipt committed while its updated cache tag is unpushed).
pub fn commit_claims_bottom_up(
    registry: &dyn Registry,
    bundle_blob: &BlobRef,
    image_claims: &[StagedClaim],
    cache_claims: &[StagedClaim],
    check_claims: &[StagedClaim],
) -> Result<(), SignerError> {
    for ic in image_claims {
        debug_assert!(ic.tag.as_str().starts_with("isha256-"));
        registry.put_claim_artifact(
            ic.tier,
            &ic.tag,
            &ic.claim_bytes,
            bundle_blob,
            &ic.payload_blobs,
        )?;
    }
    for kc in cache_claims {
        debug_assert!(kc.tag.as_str().starts_with("ksha256-"));
        registry.put_claim_artifact(
            kc.tier,
            &kc.tag,
            &kc.claim_bytes,
            bundle_blob,
            &kc.payload_blobs,
        )?;
    }
    for ac in check_claims {
        debug_assert!(ac.tag.as_str().starts_with("asha256-"));
        registry.put_claim_artifact(
            ac.tier,
            &ac.tag,
            &ac.claim_bytes,
            bundle_blob,
            &ac.payload_blobs,
        )?;
    }
    Ok(())
}
