//! Offline Sigstore `Bundle0_3` verification (`0` network calls) and opaque
//! `VerifiedClaim` issuance.
//!
//! Uses compile-time embedded Sigstore production (`PublicGood`) and GitHub
//! private-instance (`GitHub`) `TrustedRoot` bundles, enforces all 8 Fulcio CI
//! X.509 certificate extensions (`.1.8`–`.1.20`) plus SAN URI and in-toto v1
//! `(expected_tag, sha256(claim_bytes))` subject binding, and checks transitive
//! `provenance_signers` against `policy.trusted_engine_shas`.

use std::sync::OnceLock;

use sigstore_types::{Bundle, SignatureContent, Statement};
use sigstore_verify::trust_root::{
    SIGSTORE_GITHUB_TRUSTED_ROOT, SIGSTORE_PRODUCTION_TRUSTED_ROOT, TrustedRoot,
};
use sigstore_verify::{IdentityMatcher, SubjectAltName, VerificationPolicy, Verifier};
use thiserror::Error;

use crate::digest::canonicalize_claim;
use crate::types::{
    Claim, GitOid, LookupTag, Sha256Digest, SignerPolicy, SigstoreRoot, UnixSecs, VerifiedClaim,
};

/// In-toto `predicateType` URI emitted by `ci-core publish` batch attestations.
pub const BATCH_CLAIMS_PREDICATE_TYPE: &str = "urn:ci-core:batch-claims:v1";

/// Maximum tolerated forward clock skew (`5` minutes) between authenticated
/// signing timestamps and evaluation time.
pub const MAX_SIGNING_CLOCK_SKEW_SECS: u64 = 300;

/// Offline cryptographic or policy rejection during `verify_offline`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AttestError {
    /// Failed to initialize an embedded Sigstore `TrustedRoot`.
    #[error("embedded trusted root initialization error: {0}")]
    TrustRoot(String),
    /// Malformed UTF-8 or JSON in the `Bundle0_3` or `Claim`.
    #[error("malformed bundle or claim JSON: {0}")]
    MalformedJson(String),
    /// Cryptographic chain, SCT, Rekor inclusion/checkpoint, TSA, or DSSE PAE
    /// verification failed.
    #[error("sigstore cryptographic verification failed: {0}")]
    Crypto(String),
    /// Bundle was not a `Bundle0_3` DSSE in-toto v1 batch-claims statement or
    /// lacked a matching `(tag, sha256)` subject.
    #[error("in-toto statement binding failed: {0}")]
    StatementBinding(String),
    /// Fulcio X.509 CI extension (`.1.8`–`.1.20`) or SAN URI failed policy.
    #[error("Fulcio certificate policy violation: {0}")]
    FulcioPolicy(String),
    /// `Claim` lookup tag or canonical JCS representation failed validation.
    #[error("claim payload mismatch: {0}")]
    ClaimMismatch(String),
    /// Direct signer or transitive `provenance_signers` SHA is not in
    /// `policy.trusted_engine_shas`.
    #[error("revoked or untrusted engine signer SHA `{0}`")]
    UntrustedSignerSha(GitOid),
    /// Authenticated signing timestamp is in the future beyond allowed skew.
    #[error("signing_time {} exceeds eval_time {} + {MAX_SIGNING_CLOCK_SKEW_SECS}s", .signing_time.0, .eval_time.0)]
    FutureSigningTime {
        /// Authenticated bundle timestamp.
        signing_time: UnixSecs,
        /// Evaluation clock timestamp.
        eval_time: UnixSecs,
    },
}

fn public_good_verifier() -> Result<&'static Verifier, AttestError> {
    static VERIFIER: OnceLock<Result<Verifier, String>> = OnceLock::new();
    VERIFIER
        .get_or_init(|| {
            let root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)
                .map_err(|e| e.to_string())?;
            Verifier::new(&root).map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| AttestError::TrustRoot(e.clone()))
}

fn github_instance_verifier() -> Result<&'static Verifier, AttestError> {
    static VERIFIER: OnceLock<Result<Verifier, String>> = OnceLock::new();
    VERIFIER
        .get_or_init(|| {
            let root =
                TrustedRoot::from_json(SIGSTORE_GITHUB_TRUSTED_ROOT).map_err(|e| e.to_string())?;
            Verifier::new(&root).map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| AttestError::TrustRoot(e.clone()))
}

/// Verifies a Claim OCI Artifact (`raw_claim_bytes` + `bundle_bytes`) 100%
/// offline against the compile-time embedded `TrustedRoot` selected by
/// `policy.sigstore` and returns an opaque `VerifiedClaim`.
pub fn verify_offline(
    expected_tag: &LookupTag,
    raw_claim_bytes: &[u8],
    bundle_bytes: &[u8],
    policy: &SignerPolicy,
    eval_time: UnixSecs,
) -> Result<VerifiedClaim, AttestError> {
    let verifier = match policy.sigstore {
        SigstoreRoot::PublicGood => public_good_verifier()?,
        SigstoreRoot::GitHub => github_instance_verifier()?,
    };
    verify_with_verifier(
        verifier,
        policy.sigstore,
        expected_tag,
        raw_claim_bytes,
        bundle_bytes,
        policy,
        eval_time,
    )
}

#[cfg(test)]
pub(crate) fn verify_offline_with_custom_root(
    trusted_root: &TrustedRoot,
    sigstore_mode: SigstoreRoot,
    expected_tag: &LookupTag,
    raw_claim_bytes: &[u8],
    bundle_bytes: &[u8],
    policy: &SignerPolicy,
    eval_time: UnixSecs,
) -> Result<VerifiedClaim, AttestError> {
    let verifier =
        Verifier::new(trusted_root).map_err(|e| AttestError::TrustRoot(e.to_string()))?;
    verify_with_verifier(
        &verifier,
        sigstore_mode,
        expected_tag,
        raw_claim_bytes,
        bundle_bytes,
        policy,
        eval_time,
    )
}

fn verify_with_verifier(
    verifier: &Verifier,
    sigstore_mode: SigstoreRoot,
    expected_tag: &LookupTag,
    raw_claim_bytes: &[u8],
    bundle_bytes: &[u8],
    policy: &SignerPolicy,
    eval_time: UnixSecs,
) -> Result<VerifiedClaim, AttestError> {
    let bundle_str = std::str::from_utf8(bundle_bytes)
        .map_err(|e| AttestError::MalformedJson(format!("bundle UTF-8 error: {e}")))?;
    let bundle = Bundle::from_json(bundle_str)
        .map_err(|e| AttestError::MalformedJson(format!("bundle JSON error: {e}")))?;

    if bundle.media_type != sigstore_types::MediaType::Bundle0_3 {
        return Err(AttestError::StatementBinding(format!(
            "expected Sigstore Bundle0_3, got {:?}",
            bundle.media_type
        )));
    }

    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        return Err(AttestError::StatementBinding(
            "expected DSSE envelope signature content".to_owned(),
        ));
    };
    if envelope.payload_type != "application/vnd.in-toto+json" {
        return Err(AttestError::StatementBinding(format!(
            "unexpected DSSE payloadType {:?}",
            envelope.payload_type
        )));
    }

    let statement: Statement = serde_json::from_slice(envelope.payload.as_bytes())
        .map_err(|e| AttestError::MalformedJson(format!("in-toto statement parse error: {e}")))?;
    if statement.type_ != Statement::TYPE_V1 {
        return Err(AttestError::StatementBinding(format!(
            "unexpected statement _type {:?}",
            statement.type_
        )));
    }
    if statement.predicate_type != BATCH_CLAIMS_PREDICATE_TYPE {
        return Err(AttestError::StatementBinding(format!(
            "unexpected predicateType {:?} (expected {BATCH_CLAIMS_PREDICATE_TYPE:?})",
            statement.predicate_type
        )));
    }

    let claim_sha256 = Sha256Digest::hash_bytes(raw_claim_bytes);
    let subject_bound = statement.subject.iter().any(|subj| {
        subj.name == expected_tag.as_str()
            && subj
                .digest
                .sha256
                .as_ref()
                .is_some_and(|h| h.as_bytes() == claim_sha256.as_bytes())
    });
    if !subject_bound {
        return Err(AttestError::StatementBinding(format!(
            "statement subjects do not bind ({expected_tag}, {claim_sha256})"
        )));
    }

    // Build cryptographic policy for `sigstore_verify::Verifier`:
    // - `PublicGood`: full Fulcio chain + CT SCT + Rekor inclusion proof &
    //   signed checkpoint.
    // - `GitHub`: full Fulcio chain + RFC 3161 TSA timestamp (GitHub's private
    //   instance runs no transparency log and embeds no public Sigstore CT SCT).
    let base_vpolicy = VerificationPolicy::any_identity().require_issuer(&policy.oidc_issuer);
    let vpolicy = match sigstore_mode {
        SigstoreRoot::PublicGood => base_vpolicy,
        SigstoreRoot::GitHub => base_vpolicy.skip_tlog_unsafe().skip_sct(),
    };

    let vresult = verifier
        .verify(raw_claim_bytes, &bundle, &vpolicy)
        .map_err(|e| AttestError::Crypto(e.to_string()))?;

    if !vresult.certificate_verified() {
        return Err(AttestError::Crypto(
            "certificate chain was not verified".to_owned(),
        ));
    }

    let signing_secs_i64 = match sigstore_mode {
        SigstoreRoot::PublicGood => {
            if !vresult.sct_verified() || !vresult.tlog_verified() {
                return Err(AttestError::Crypto(
                    "PublicGood bundle missing verified CT SCT or Rekor inclusion proof".to_owned(),
                ));
            }
            vresult
                .integrated_time()
                .ok_or_else(|| {
                    AttestError::Crypto(
                        "PublicGood bundle missing authenticated Rekor integrated_time".to_owned(),
                    )
                })?
                .as_second()
        }
        SigstoreRoot::GitHub => {
            if bundle
                .verification_material
                .timestamp_verification_data
                .rfc3161_timestamps
                .is_empty()
            {
                return Err(AttestError::Crypto(
                    "GitHub instance bundle missing RFC 3161 TSA timestamp".to_owned(),
                ));
            }
            vresult
                .verified_timestamps()
                .iter()
                .copied()
                .min()
                .ok_or_else(|| {
                    AttestError::Crypto(
                        "GitHub instance bundle yielded no verified TSA timestamps".to_owned(),
                    )
                })?
                .as_second()
        }
    };
    if signing_secs_i64 < 0 {
        return Err(AttestError::Crypto(format!(
            "negative signing timestamp {signing_secs_i64}"
        )));
    }
    let signing_time = UnixSecs(signing_secs_i64 as u64);
    if signing_time > eval_time.saturating_add(MAX_SIGNING_CLOCK_SKEW_SECS) {
        return Err(AttestError::FutureSigningTime {
            signing_time,
            eval_time,
        });
    }

    // Enforce all 8 Fulcio OIDs (`.1.8`, `.1.9`, `.1.10`, `.1.11`, `.1.14`,
    // `.1.15`, `.1.17`, `.1.20`) and exact SAN URI (`.1.18` `buildConfigURI` is
    // deliberately unpinned so receipts share across RepoRuleset & OrgRuleset).
    if vresult.issuer() != Some(policy.oidc_issuer.as_str()) {
        return Err(AttestError::FulcioPolicy(format!(
            "OID .1.8 issuer {:?} != {:?}",
            vresult.issuer(),
            policy.oidc_issuer
        )));
    }
    let cert_info = vresult.certificate().ok_or_else(|| {
        AttestError::FulcioPolicy("verified bundle missing leaf CertificateInfo".to_owned())
    })?;
    let ci = &cert_info.ci_claims;

    let raw_signer_sha = ci.build_signer_digest.as_deref().ok_or_else(|| {
        AttestError::FulcioPolicy("missing OID .1.10 buildSignerDigest".to_owned())
    })?;
    let signer_sha = GitOid::from_hex(raw_signer_sha).map_err(|_| {
        AttestError::FulcioPolicy(format!(
            "OID .1.10 buildSignerDigest {raw_signer_sha:?} is not a 40-hex GitOid"
        ))
    })?;
    if !policy.trusted_engine_shas.contains(&signer_sha) {
        return Err(AttestError::UntrustedSignerSha(signer_sha));
    }

    let expected_signer_uri = format!(
        "https://github.com/{}@{}",
        policy.trusted_engine_workflow, signer_sha
    );
    let id_matcher = IdentityMatcher::Uri(expected_signer_uri.clone());
    if !vresult
        .identity()
        .is_some_and(|san: &SubjectAltName| id_matcher.matches(san))
    {
        return Err(AttestError::FulcioPolicy(format!(
            "SAN URI {:?} != {:?}",
            vresult.identity(),
            expected_signer_uri
        )));
    }
    if ci.build_signer_uri.as_deref() != Some(expected_signer_uri.as_str()) {
        return Err(AttestError::FulcioPolicy(format!(
            "OID .1.9 buildSignerURI {:?} != {:?}",
            ci.build_signer_uri, expected_signer_uri
        )));
    }

    if ci.runner_environment.as_deref() != Some("github-hosted") {
        return Err(AttestError::FulcioPolicy(format!(
            "OID .1.11 runnerEnvironment {:?} != \"github-hosted\"",
            ci.runner_environment
        )));
    }

    let expected_repo_id = policy.repo_id.to_string();
    if ci.source_repository_identifier.as_deref() != Some(expected_repo_id.as_str()) {
        return Err(AttestError::FulcioPolicy(format!(
            "OID .1.15 sourceRepositoryIdentifier {:?} != {:?}",
            ci.source_repository_identifier, expected_repo_id
        )));
    }

    let expected_owner_id = policy.owner_id.to_string();
    if ci.source_repository_owner_identifier.as_deref() != Some(expected_owner_id.as_str()) {
        return Err(AttestError::FulcioPolicy(format!(
            "OID .1.17 sourceRepositoryOwnerIdentifier {:?} != {:?}",
            ci.source_repository_owner_identifier, expected_owner_id
        )));
    }

    let trigger = ci
        .build_trigger
        .as_deref()
        .ok_or_else(|| AttestError::FulcioPolicy("missing OID .1.20 buildTrigger".to_owned()))?;
    let source_ref = ci.source_repository_ref.as_deref().ok_or_else(|| {
        AttestError::FulcioPolicy("missing OID .1.14 sourceRepositoryRef".to_owned())
    })?;
    match trigger {
        "push" => {
            let expected_ref = format!("refs/heads/{}", policy.default_branch);
            if source_ref != expected_ref {
                return Err(AttestError::FulcioPolicy(format!(
                    "OID .1.14 sourceRepositoryRef {source_ref:?} != {expected_ref:?} for push"
                )));
            }
        }
        "merge_group" => {
            let expected_prefix =
                format!("refs/heads/gh-readonly-queue/{}/", policy.default_branch);
            let suffix = source_ref
                .strip_prefix(&expected_prefix)
                .unwrap_or_default();
            if suffix.is_empty() {
                return Err(AttestError::FulcioPolicy(format!(
                    "OID .1.14 sourceRepositoryRef {source_ref:?} does not match prefix {expected_prefix:?}"
                )));
            }
        }
        other => {
            return Err(AttestError::FulcioPolicy(format!(
                "OID .1.20 buildTrigger {other:?} is untrusted (expected \"push\" or \"merge_group\")"
            )));
        }
    }

    let claim: Claim = serde_json::from_slice(raw_claim_bytes)
        .map_err(|e| AttestError::MalformedJson(format!("Claim JSON parse error: {e}")))?;
    if &claim.lookup_tag() != expected_tag {
        return Err(AttestError::ClaimMismatch(format!(
            "claim.lookup_tag() `{}` != expected `{expected_tag}`",
            claim.lookup_tag()
        )));
    }
    let (canonical_bytes, _) = canonicalize_claim(&claim).map_err(AttestError::ClaimMismatch)?;
    if canonical_bytes != raw_claim_bytes {
        return Err(AttestError::ClaimMismatch(
            "raw_claim_bytes are not canonical RFC 8785 JCS".to_owned(),
        ));
    }

    // Enforce transitive provenance validity across upstream reused images and
    // hydrated caches.
    if let Some(prov_signers) = claim.provenance_signers() {
        for upstream_sha in prov_signers {
            if !policy.trusted_engine_shas.contains(upstream_sha) {
                return Err(AttestError::UntrustedSignerSha(*upstream_sha));
            }
        }
    }

    Ok(VerifiedClaim::new(claim, signing_time, signer_sha))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::str::FromStr;

    use base64::Engine as _;
    use const_oid::ObjectIdentifier;
    use const_oid::db::rfc5280::{
        ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS, ID_CE_EXT_KEY_USAGE,
        ID_CE_KEY_USAGE, ID_CE_SUBJECT_ALT_NAME, ID_CE_SUBJECT_KEY_IDENTIFIER, ID_KP_CODE_SIGNING,
    };
    use const_oid::db::rfc6962::CT_PRECERT_SCTS;
    use der::asn1::{BitString, Ia5String, OctetString, UtcTime, Utf8StringRef};
    use der::{Decode, Encode};
    use sigstore_crypto::{KeyPair, compute_key_hint, sha256};
    use sigstore_types::{DsseEnvelope, DsseSignature, PayloadBytes, pae};
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::Certificate;
    use x509_cert::certificate::{TbsCertificate, Version as X509Version};
    use x509_cert::ext::Extension;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::{
        AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
        SubjectAltName as X509San, SubjectKeyIdentifier,
    };
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};

    use super::*;
    use crate::types::{CacheSlotId, NonEmptyVec, OutputDigest, OutputName, WorkflowUri};

    const ECDSA_WITH_SHA256_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

    #[derive(Clone)]
    struct FulcioLeafClaims {
        san_uri: String,
        issuer_v2: String,
        build_signer_uri: Option<String>,
        build_signer_digest: Option<String>,
        runner_environment: Option<String>,
        source_repo_ref: Option<String>,
        source_repo_id: Option<String>,
        source_owner_id: Option<String>,
        build_config_uri: Option<String>,
        build_trigger: Option<String>,
    }

    impl FulcioLeafClaims {
        fn valid_default(signer_sha: &str, trigger: &str, source_ref: &str) -> Self {
            let wf_uri =
                format!("https://github.com/joshlf/ci-core/.github/workflows/ci.yml@{signer_sha}");
            Self {
                san_uri: wf_uri.clone(),
                issuer_v2: "https://token.actions.githubusercontent.com".to_owned(),
                build_signer_uri: Some(wf_uri),
                build_signer_digest: Some(signer_sha.to_owned()),
                runner_environment: Some("github-hosted".to_owned()),
                source_repo_ref: Some(source_ref.to_owned()),
                source_repo_id: Some("534354967".to_owned()),
                source_owner_id: Some("1342004".to_owned()),
                build_config_uri: Some(
                    "https://github.com/google/zerocopy/.github/workflows/ci.yml@refs/heads/main"
                        .to_owned(),
                ),
                build_trigger: Some(trigger.to_owned()),
            }
        }
    }

    struct TestSigstorePki {
        ca_key: KeyPair,
        ca_cert_der: Vec<u8>,
        ca_spki_der: Vec<u8>,
        ct_key: KeyPair,
        ct_log_id: [u8; 32],
        rekor_key: KeyPair,
        rekor_log_id: [u8; 32],
        trusted_root: TrustedRoot,
    }

    fn ecdsa_sha256_alg() -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA256_OID,
            parameters: None,
        }
    }

    fn utc_time(secs: u64) -> Time {
        Time::UtcTime(UtcTime::from_unix_duration(std::time::Duration::from_secs(secs)).unwrap())
    }

    fn sign_tbs(tbs: &TbsCertificate, signer: &KeyPair) -> Vec<u8> {
        let tbs_der = tbs.to_der().unwrap();
        let sig = signer.sign(&tbs_der).unwrap();
        let cert = Certificate {
            tbs_certificate: tbs.clone(),
            signature_algorithm: ecdsa_sha256_alg(),
            signature: BitString::from_bytes(sig.as_bytes()).unwrap(),
        };
        cert.to_der().unwrap()
    }

    fn fulcio_utf8_ext(arc_num: u32, val: &str) -> Extension {
        let oid = ObjectIdentifier::new_unwrap(&format!("1.3.6.1.4.1.57264.1.{arc_num}"));
        let der_utf8 = Utf8StringRef::new(val).unwrap().to_der().unwrap();
        Extension {
            extn_id: oid,
            critical: false,
            extn_value: OctetString::new(der_utf8).unwrap(),
        }
    }

    impl TestSigstorePki {
        fn generate() -> Self {
            let ca_key = KeyPair::generate_ecdsa_p256().unwrap();
            let ca_spki_der = ca_key.public_key_der().unwrap().as_bytes().to_vec();
            let ca_spki = SubjectPublicKeyInfoOwned::from_der(&ca_spki_der).unwrap();
            let ca_ski_bytes = *sha256(&ca_spki_der).as_bytes();
            let subject = Name::from_str("CN=Test Fulcio Root,O=ci-core-test").unwrap();
            let ca_exts = vec![
                Extension {
                    extn_id: ID_CE_BASIC_CONSTRAINTS,
                    critical: true,
                    extn_value: OctetString::new(
                        BasicConstraints {
                            ca: true,
                            path_len_constraint: None,
                        }
                        .to_der()
                        .unwrap(),
                    )
                    .unwrap(),
                },
                Extension {
                    extn_id: ID_CE_KEY_USAGE,
                    critical: true,
                    extn_value: OctetString::new(
                        KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
                            .to_der()
                            .unwrap(),
                    )
                    .unwrap(),
                },
                Extension {
                    extn_id: ID_CE_SUBJECT_KEY_IDENTIFIER,
                    critical: false,
                    extn_value: OctetString::new(
                        SubjectKeyIdentifier(OctetString::new(ca_ski_bytes).unwrap())
                            .to_der()
                            .unwrap(),
                    )
                    .unwrap(),
                },
            ];
            let ca_tbs = TbsCertificate {
                version: X509Version::V3,
                serial_number: SerialNumber::new(&[1u8]).unwrap(),
                signature: ecdsa_sha256_alg(),
                issuer: subject.clone(),
                validity: Validity {
                    not_before: utc_time(1_700_000_000),
                    not_after: utc_time(2_000_000_000),
                },
                subject,
                subject_public_key_info: ca_spki,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: Some(ca_exts),
            };
            let ca_cert_der = sign_tbs(&ca_tbs, &ca_key);

            let ct_key = KeyPair::generate_ecdsa_p256().unwrap();
            let ct_spki = ct_key.public_key_der().unwrap();
            let ct_log_id = *sha256(ct_spki.as_bytes()).as_bytes();

            let rekor_key = KeyPair::generate_ecdsa_p256().unwrap();
            let rekor_spki = rekor_key.public_key_der().unwrap();
            let rekor_log_id = *sha256(rekor_spki.as_bytes()).as_bytes();

            let b64 = base64::engine::general_purpose::STANDARD;
            let root_json = serde_json::json!({
                "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
                "tlogs": [{
                    "baseUrl": "https://rekor.ci-core.test",
                    "hashAlgorithm": "SHA2_256",
                    "publicKey": {
                        "rawBytes": b64.encode(rekor_spki.as_bytes()),
                        "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                        "validFor": { "start": "2023-11-14T22:13:20Z" }
                    },
                    "logId": { "keyId": b64.encode(rekor_log_id) }
                }],
                "certificateAuthorities": [{
                    "subject": { "organization": "ci-core-test", "commonName": "Test Fulcio Root" },
                    "uri": "https://fulcio.ci-core.test",
                    "certChain": {
                        "certificates": [{ "rawBytes": b64.encode(&ca_cert_der) }]
                    },
                    "validFor": { "start": "2023-11-14T22:13:20Z" }
                }],
                "ctlogs": [{
                    "baseUrl": "https://ctfe.ci-core.test",
                    "hashAlgorithm": "SHA2_256",
                    "publicKey": {
                        "rawBytes": b64.encode(ct_spki.as_bytes()),
                        "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                        "validFor": { "start": "2023-11-14T22:13:20Z" }
                    },
                    "logId": { "keyId": b64.encode(ct_log_id) }
                }],
                "timestampAuthorities": []
            });
            let trusted_root =
                TrustedRoot::from_json(&serde_json::to_string(&root_json).unwrap()).unwrap();

            Self {
                ca_key,
                ca_cert_der,
                ca_spki_der,
                ct_key,
                ct_log_id,
                rekor_key,
                rekor_log_id,
                trusted_root,
            }
        }

        fn mint_bundle(
            &self,
            claims: &FulcioLeafClaims,
            subjects: &[(String, Sha256Digest)],
            predicate_type: &str,
            integrated_secs: u64,
        ) -> Vec<u8> {
            let leaf_key = KeyPair::generate_ecdsa_p256().unwrap();
            let leaf_spki_der = leaf_key.public_key_der().unwrap().as_bytes().to_vec();
            let leaf_spki = SubjectPublicKeyInfoOwned::from_der(&leaf_spki_der).unwrap();
            let leaf_ski = *sha256(&leaf_spki_der).as_bytes();
            let ca_ski = *sha256(&self.ca_spki_der).as_bytes();
            let issuer_name = Name::from_str("CN=Test Fulcio Root,O=ci-core-test").unwrap();
            let empty_subject = Name::default();

            let san = X509San(vec![GeneralName::UniformResourceIdentifier(
                Ia5String::new(&claims.san_uri).unwrap(),
            )]);
            let mut exts = vec![
                Extension {
                    extn_id: ID_CE_BASIC_CONSTRAINTS,
                    critical: true,
                    extn_value: OctetString::new(
                        BasicConstraints {
                            ca: false,
                            path_len_constraint: None,
                        }
                        .to_der()
                        .unwrap(),
                    )
                    .unwrap(),
                },
                Extension {
                    extn_id: ID_CE_KEY_USAGE,
                    critical: true,
                    extn_value: OctetString::new(
                        KeyUsage(KeyUsages::DigitalSignature.into())
                            .to_der()
                            .unwrap(),
                    )
                    .unwrap(),
                },
                Extension {
                    extn_id: ID_CE_EXT_KEY_USAGE,
                    critical: false,
                    extn_value: OctetString::new(
                        ExtendedKeyUsage(vec![ID_KP_CODE_SIGNING]).to_der().unwrap(),
                    )
                    .unwrap(),
                },
                Extension {
                    extn_id: ID_CE_SUBJECT_KEY_IDENTIFIER,
                    critical: false,
                    extn_value: OctetString::new(
                        SubjectKeyIdentifier(OctetString::new(leaf_ski).unwrap())
                            .to_der()
                            .unwrap(),
                    )
                    .unwrap(),
                },
                Extension {
                    extn_id: ID_CE_AUTHORITY_KEY_IDENTIFIER,
                    critical: false,
                    extn_value: OctetString::new(
                        AuthorityKeyIdentifier {
                            key_identifier: Some(OctetString::new(ca_ski).unwrap()),
                            authority_cert_issuer: None,
                            authority_cert_serial_number: None,
                        }
                        .to_der()
                        .unwrap(),
                    )
                    .unwrap(),
                },
                Extension {
                    extn_id: ID_CE_SUBJECT_ALT_NAME,
                    critical: true,
                    extn_value: OctetString::new(san.to_der().unwrap()).unwrap(),
                },
                fulcio_utf8_ext(8, &claims.issuer_v2),
            ];
            if let Some(v) = &claims.build_signer_uri {
                exts.push(fulcio_utf8_ext(9, v));
            }
            if let Some(v) = &claims.build_signer_digest {
                exts.push(fulcio_utf8_ext(10, v));
            }
            if let Some(v) = &claims.runner_environment {
                exts.push(fulcio_utf8_ext(11, v));
            }
            if let Some(v) = &claims.source_repo_ref {
                exts.push(fulcio_utf8_ext(14, v));
            }
            if let Some(v) = &claims.source_repo_id {
                exts.push(fulcio_utf8_ext(15, v));
            }
            if let Some(v) = &claims.source_owner_id {
                exts.push(fulcio_utf8_ext(17, v));
            }
            if let Some(v) = &claims.build_config_uri {
                exts.push(fulcio_utf8_ext(18, v));
            }
            if let Some(v) = &claims.build_trigger {
                exts.push(fulcio_utf8_ext(20, v));
            }

            let mut tbs = TbsCertificate {
                version: X509Version::V3,
                serial_number: SerialNumber::new(&[2u8]).unwrap(),
                signature: ecdsa_sha256_alg(),
                issuer: issuer_name,
                validity: Validity {
                    not_before: utc_time(integrated_secs.saturating_sub(300)),
                    not_after: utc_time(integrated_secs + 600),
                },
                subject: empty_subject,
                subject_public_key_info: leaf_spki,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: Some(exts.clone()),
            };

            // Build RFC 6962 v1 PrecertEntry SCT signed by `ct_key`.
            let precert_tbs_der = tbs.to_der().unwrap();
            let issuer_key_hash = *sha256(&self.ca_spki_der).as_bytes();
            let sct_ts_ms = integrated_secs * 1000;
            let mut sct_signed_data = Vec::new();
            sct_signed_data.push(0u8); // Version::V1
            sct_signed_data.push(0u8); // SignatureType::CertificateTimestamp
            sct_signed_data.extend_from_slice(&sct_ts_ms.to_be_bytes());
            sct_signed_data.extend_from_slice(&1u16.to_be_bytes()); // LogEntryType::PrecertEntry
            sct_signed_data.extend_from_slice(&issuer_key_hash);
            let tbs_len = precert_tbs_der.len() as u32;
            sct_signed_data.extend_from_slice(&tbs_len.to_be_bytes()[1..4]); // u24 len
            sct_signed_data.extend_from_slice(&precert_tbs_der);
            sct_signed_data.extend_from_slice(&0u16.to_be_bytes()); // empty extensions

            let ct_sig = self.ct_key.sign(&sct_signed_data).unwrap();
            let mut single_sct = Vec::new();
            single_sct.push(0u8); // v1
            single_sct.extend_from_slice(&self.ct_log_id);
            single_sct.extend_from_slice(&sct_ts_ms.to_be_bytes());
            single_sct.extend_from_slice(&0u16.to_be_bytes()); // extensions len
            single_sct.extend_from_slice(&0x0403u16.to_be_bytes()); // ECDSA_SHA256
            single_sct.extend_from_slice(&(ct_sig.as_bytes().len() as u16).to_be_bytes());
            single_sct.extend_from_slice(ct_sig.as_bytes());

            let mut sct_list_tls = Vec::new();
            let inner_total = (2 + single_sct.len()) as u16;
            sct_list_tls.extend_from_slice(&inner_total.to_be_bytes());
            sct_list_tls.extend_from_slice(&(single_sct.len() as u16).to_be_bytes());
            sct_list_tls.extend_from_slice(&single_sct);
            // X.509 CT_PRECERT_SCTS extension wraps the TLS SCT list in an ASN.1 OCTET STRING.
            let sct_octet_der = OctetString::new(sct_list_tls).unwrap().to_der().unwrap();
            exts.push(Extension {
                extn_id: CT_PRECERT_SCTS,
                critical: false,
                extn_value: OctetString::new(sct_octet_der).unwrap(),
            });
            tbs.extensions = Some(exts);
            let leaf_cert_der = sign_tbs(&tbs, &self.ca_key);
            let _ = &self.ca_cert_der;

            // Build in-toto Statement + DSSE envelope signed by `leaf_key`.
            let subj_json: Vec<serde_json::Value> = subjects
                .iter()
                .map(|(n, d)| {
                    serde_json::json!({
                        "name": n,
                        "digest": { "sha256": d.to_hex() }
                    })
                })
                .collect();
            let stmt = serde_json::json!({
                "_type": "https://in-toto.io/Statement/v1",
                "subject": subj_json,
                "predicateType": predicate_type,
                "predicate": { "schema_version": 1 }
            });
            let payload_bytes = serde_json::to_vec(&stmt).unwrap();
            let dsse_sig = leaf_key
                .sign(&pae("application/vnd.in-toto+json", &payload_bytes))
                .unwrap();
            let envelope = DsseEnvelope::new(
                "application/vnd.in-toto+json",
                PayloadBytes::new(payload_bytes.clone()),
                DsseSignature::new(dsse_sig.clone(), sigstore_types::KeyId::default()),
            );

            // Build Rekor v1 dsse entry (`tree_size = 1`, `log_index = 0`).
            let leaf_pem = format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                base64::engine::general_purpose::STANDARD.encode(&leaf_cert_der)
            );
            let rekor_body_json = serde_json::json!({
                "apiVersion": "0.0.1",
                "kind": "dsse",
                "spec": {
                    "envelopeHash": {
                        "algorithm": "sha256",
                        "value": sha256(&serde_json::to_vec(&envelope).unwrap()).to_hex()
                    },
                    "payloadHash": {
                        "algorithm": "sha256",
                        "value": sha256(&payload_bytes).to_hex()
                    },
                    "signatures": [{
                        "signature": dsse_sig.to_base64(),
                        "verifier": base64::engine::general_purpose::STANDARD.encode(leaf_pem.as_bytes())
                    }]
                }
            });
            let canon_body = serde_json_canonicalizer::to_vec(&rekor_body_json).unwrap();
            let root_hash = sigstore_merkle::hash_leaf(&canon_body);
            let b64 = base64::engine::general_purpose::STANDARD;
            let cp_body = format!(
                "rekor.ci-core.test - 1\n1\n{}\n",
                b64.encode(root_hash.as_bytes())
            );
            let cp_sig = self.rekor_key.sign(cp_body.as_bytes()).unwrap();
            let hint = compute_key_hint(&self.rekor_key.public_key_der().unwrap());
            let mut note_sig_bytes = hint.as_bytes().to_vec();
            note_sig_bytes.extend_from_slice(cp_sig.as_bytes());
            let cp_envelope = format!(
                "{cp_body}\n\u{2014} rekor.ci-core.test {}\n",
                b64.encode(note_sig_bytes)
            );

            // Sign Rekor v1 SET (`SignedEntryTimestamp`).
            let set_payload = serde_json::json!({
                "body": b64.encode(&canon_body),
                "integratedTime": integrated_secs as i64,
                "logID": hex::encode(self.rekor_log_id),
                "logIndex": 0
            });
            let set_canon = serde_json_canonicalizer::to_vec(&set_payload).unwrap();
            let set_sig = self.rekor_key.sign(&set_canon).unwrap();

            let bundle_json = serde_json::json!({
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "certificate": {
                        "rawBytes": b64.encode(&leaf_cert_der)
                    },
                    "tlogEntries": [{
                        "logIndex": "0",
                        "logId": { "keyId": b64.encode(self.rekor_log_id) },
                        "kindVersion": { "kind": "dsse", "version": "0.0.1" },
                        "integratedTime": integrated_secs.to_string(),
                        "inclusionPromise": {
                            "signedEntryTimestamp": b64.encode(set_sig.as_bytes())
                        },
                        "inclusionProof": {
                            "logIndex": "0",
                            "rootHash": b64.encode(root_hash.as_bytes()),
                            "treeSize": "1",
                            "hashes": [],
                            "checkpoint": { "envelope": cp_envelope }
                        },
                        "canonicalizedBody": b64.encode(&canon_body)
                    }],
                    "timestampVerificationData": { "rfc3161Timestamps": [] }
                },
                "dsseEnvelope": envelope
            });
            serde_json::to_vec(&bundle_json).unwrap()
        }
    }

    fn sample_policy(shas: &[&str]) -> SignerPolicy {
        let parsed: Vec<GitOid> = shas.iter().map(|s| GitOid::from_hex(s).unwrap()).collect();
        SignerPolicy {
            repo_id: 534354967,
            owner_id: 1342004,
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
            trusted_engine_shas: NonEmptyVec::new(parsed).unwrap(),
        }
    }

    #[test]
    fn offline_verifier_enforces_all_fulcio_oids_and_transitive_provenance_revocation() {
        let pki = TestSigstorePki::generate();
        let s0 = "0000000000000000000000000000000000000000";
        let s1 = "1111111111111111111111111111111111111111";
        let s2 = "2222222222222222222222222222222222222222";
        // Use a realistic past timestamp <= now so Rekor's `not_in_future` check passes.
        let sign_ts = 1_740_000_000u64;
        let eval_ts = UnixSecs(sign_ts + 60);

        let action_dig = Sha256Digest::hash_bytes(b"check-action-1");
        let mut outputs = BTreeMap::new();
        outputs.insert(
            OutputName::new("lcov.info").unwrap(),
            OutputDigest {
                sha256: Sha256Digest::hash_bytes(b"coverage"),
                size_bytes: 8,
            },
        );
        let mut prov = BTreeSet::new();
        prov.insert(GitOid::from_hex(s0).unwrap());
        let check_claim = Claim::Check {
            action: action_dig,
            outputs,
            provenance_signers: prov,
        };
        let (claim_bytes, claim_sha) = canonicalize_claim(&check_claim).unwrap();
        let tag = check_claim.lookup_tag();

        // 1. Happy path on `push` (`refs/heads/main`) when both S0 and S1 are trusted.
        let leaf = FulcioLeafClaims::valid_default(s1, "push", "refs/heads/main");
        let bundle = pki.mint_bundle(
            &leaf,
            &[(tag.as_str().to_owned(), claim_sha)],
            BATCH_CLAIMS_PREDICATE_TYPE,
            sign_ts,
        );
        let pol_both = sample_policy(&[s0, s1]);
        let vc = verify_offline_with_custom_root(
            &pki.trusted_root,
            SigstoreRoot::PublicGood,
            &tag,
            &claim_bytes,
            &bundle,
            &pol_both,
            eval_ts,
        )
        .expect("valid push bundle should verify");
        assert_eq!(vc.signer_sha(), GitOid::from_hex(s1).unwrap());
        assert_eq!(vc.signing_time(), UnixSecs(sign_ts));

        // 2. Transitive provenance revocation (`C5.1`): revoking `S0` rejects an
        // `S1`-signed receipt that consumed an `S0`-signed upstream image/cache!
        let pol_revoked_s0 = sample_policy(&[s1, s2]);
        let err = verify_offline_with_custom_root(
            &pki.trusted_root,
            SigstoreRoot::PublicGood,
            &tag,
            &claim_bytes,
            &bundle,
            &pol_revoked_s0,
            eval_ts,
        )
        .unwrap_err();
        assert_eq!(
            err,
            AttestError::UntrustedSignerSha(GitOid::from_hex(s0).unwrap())
        );

        // 3. Direct signer revocation: revoking `S1` rejects immediately.
        let pol_only_s0 = sample_policy(&[s0]);
        let err = verify_offline_with_custom_root(
            &pki.trusted_root,
            SigstoreRoot::PublicGood,
            &tag,
            &claim_bytes,
            &bundle,
            &pol_only_s0,
            eval_ts,
        )
        .unwrap_err();
        assert_eq!(
            err,
            AttestError::UntrustedSignerSha(GitOid::from_hex(s1).unwrap())
        );

        // 4. Unpinned `.1.18` (`buildConfigURI`) shares receipts seamlessly between
        // RepoRuleset (`ci.yml`) and OrgRuleset (`google/ci-config/.../org.yml`).
        let mut org_leaf = FulcioLeafClaims::valid_default(
            s1,
            "merge_group",
            "refs/heads/gh-readonly-queue/main/pr-42-deadbeef",
        );
        org_leaf.build_config_uri = Some(
            "https://github.com/google/ci-config/.github/workflows/org-ci.yml@refs/heads/main"
                .to_owned(),
        );
        let mg_bundle = pki.mint_bundle(
            &org_leaf,
            &[(tag.as_str().to_owned(), claim_sha)],
            BATCH_CLAIMS_PREDICATE_TYPE,
            sign_ts,
        );
        verify_offline_with_custom_root(
            &pki.trusted_root,
            SigstoreRoot::PublicGood,
            &tag,
            &claim_bytes,
            &mg_bundle,
            &pol_both,
            eval_ts,
        )
        .expect("merge_group bundle with OrgRuleset .1.18 must verify");

        // 5. Reject every invalid Fulcio OID / SAN / timestamp / non-JCS mutation:
        // (a) `.1.20` = "pull_request"
        let mut bad_trigger = leaf.clone();
        bad_trigger.build_trigger = Some("pull_request".to_owned());
        let b = pki.mint_bundle(
            &bad_trigger,
            &[(tag.as_str().to_owned(), claim_sha)],
            BATCH_CLAIMS_PREDICATE_TYPE,
            sign_ts,
        );
        assert!(matches!(
            verify_offline_with_custom_root(
                &pki.trusted_root,
                SigstoreRoot::PublicGood,
                &tag,
                &claim_bytes,
                &b,
                &pol_both,
                eval_ts
            ),
            Err(AttestError::FulcioPolicy(_))
        ));

        // (b) `.1.14` wrong branch on `push` and empty queue suffix on `merge_group`
        let mut bad_push_ref = leaf.clone();
        bad_push_ref.source_repo_ref = Some("refs/heads/feature".to_owned());
        let b = pki.mint_bundle(
            &bad_push_ref,
            &[(tag.as_str().to_owned(), claim_sha)],
            BATCH_CLAIMS_PREDICATE_TYPE,
            sign_ts,
        );
        assert!(matches!(
            verify_offline_with_custom_root(
                &pki.trusted_root,
                SigstoreRoot::PublicGood,
                &tag,
                &claim_bytes,
                &b,
                &pol_both,
                eval_ts
            ),
            Err(AttestError::FulcioPolicy(_))
        ));

        let mut bad_mg_ref = leaf.clone();
        bad_mg_ref.build_trigger = Some("merge_group".to_owned());
        bad_mg_ref.source_repo_ref = Some("refs/heads/gh-readonly-queue/main/".to_owned());
        let b = pki.mint_bundle(
            &bad_mg_ref,
            &[(tag.as_str().to_owned(), claim_sha)],
            BATCH_CLAIMS_PREDICATE_TYPE,
            sign_ts,
        );
        assert!(matches!(
            verify_offline_with_custom_root(
                &pki.trusted_root,
                SigstoreRoot::PublicGood,
                &tag,
                &claim_bytes,
                &b,
                &pol_both,
                eval_ts
            ),
            Err(AttestError::FulcioPolicy(_))
        ));

        // (c) `.1.11` self-hosted runner
        let mut self_hosted = leaf.clone();
        self_hosted.runner_environment = Some("self-hosted".to_owned());
        let b = pki.mint_bundle(
            &self_hosted,
            &[(tag.as_str().to_owned(), claim_sha)],
            BATCH_CLAIMS_PREDICATE_TYPE,
            sign_ts,
        );
        assert!(matches!(
            verify_offline_with_custom_root(
                &pki.trusted_root,
                SigstoreRoot::PublicGood,
                &tag,
                &claim_bytes,
                &b,
                &pol_both,
                eval_ts
            ),
            Err(AttestError::FulcioPolicy(_))
        ));

        // (d) `.1.15` wrong repo_id & `.1.17` wrong owner_id & `.1.9` / SAN mismatch
        let mut wrong_repo = leaf.clone();
        wrong_repo.source_repo_id = Some("999999".to_owned());
        let b = pki.mint_bundle(
            &wrong_repo,
            &[(tag.as_str().to_owned(), claim_sha)],
            BATCH_CLAIMS_PREDICATE_TYPE,
            sign_ts,
        );
        assert!(matches!(
            verify_offline_with_custom_root(
                &pki.trusted_root,
                SigstoreRoot::PublicGood,
                &tag,
                &claim_bytes,
                &b,
                &pol_both,
                eval_ts
            ),
            Err(AttestError::FulcioPolicy(_))
        ));

        let mut wrong_owner = leaf.clone();
        wrong_owner.source_owner_id = Some("999999".to_owned());
        let b = pki.mint_bundle(
            &wrong_owner,
            &[(tag.as_str().to_owned(), claim_sha)],
            BATCH_CLAIMS_PREDICATE_TYPE,
            sign_ts,
        );
        assert!(matches!(
            verify_offline_with_custom_root(
                &pki.trusted_root,
                SigstoreRoot::PublicGood,
                &tag,
                &claim_bytes,
                &b,
                &pol_both,
                eval_ts
            ),
            Err(AttestError::FulcioPolicy(_))
        ));

        let mut wrong_san = leaf.clone();
        wrong_san.san_uri =
            format!("https://github.com/evil/ci-core/.github/workflows/ci.yml@{s1}");
        let b = pki.mint_bundle(
            &wrong_san,
            &[(tag.as_str().to_owned(), claim_sha)],
            BATCH_CLAIMS_PREDICATE_TYPE,
            sign_ts,
        );
        assert!(matches!(
            verify_offline_with_custom_root(
                &pki.trusted_root,
                SigstoreRoot::PublicGood,
                &tag,
                &claim_bytes,
                &b,
                &pol_both,
                eval_ts
            ),
            Err(AttestError::FulcioPolicy(_))
        ));

        // (e) Future signing timestamp (`signing_time > eval_time + 300`)
        assert!(matches!(
            verify_offline_with_custom_root(
                &pki.trusted_root,
                SigstoreRoot::PublicGood,
                &tag,
                &claim_bytes,
                &bundle,
                &pol_both,
                UnixSecs(sign_ts - 301)
            ),
            Err(AttestError::FutureSigningTime { .. })
        ));

        // (f) Subject name substitution (same digest, wrong `expected_tag`)
        let other_cache = Claim::Cache {
            key: Sha256Digest::hash_bytes(b"k1"),
            slot: CacheSlotId::new("miri-v1").unwrap(),
            archive: Sha256Digest::hash_bytes(b"arch"),
            size_bytes: 42,
            provenance_signers: BTreeSet::new(),
        };
        let wrong_tag = other_cache.lookup_tag();
        let b_wrong_subj = pki.mint_bundle(
            &leaf,
            &[(wrong_tag.as_str().to_owned(), claim_sha)],
            BATCH_CLAIMS_PREDICATE_TYPE,
            sign_ts,
        );
        assert!(matches!(
            verify_offline_with_custom_root(
                &pki.trusted_root,
                SigstoreRoot::PublicGood,
                &tag,
                &claim_bytes,
                &b_wrong_subj,
                &pol_both,
                eval_ts
            ),
            Err(AttestError::StatementBinding(_))
        ));

        // (g) Non-JCS formatting of `raw_claim_bytes` (even when validly signed!)
        let mut non_jcs = claim_bytes.clone();
        non_jcs.push(b'\n');
        let non_jcs_sha = Sha256Digest::hash_bytes(&non_jcs);
        let b_non_jcs = pki.mint_bundle(
            &leaf,
            &[(tag.as_str().to_owned(), non_jcs_sha)],
            BATCH_CLAIMS_PREDICATE_TYPE,
            sign_ts,
        );
        assert!(matches!(
            verify_offline_with_custom_root(
                &pki.trusted_root,
                SigstoreRoot::PublicGood,
                &tag,
                &non_jcs,
                &b_non_jcs,
                &pol_both,
                eval_ts
            ),
            Err(AttestError::ClaimMismatch(_))
        ));
    }
}
