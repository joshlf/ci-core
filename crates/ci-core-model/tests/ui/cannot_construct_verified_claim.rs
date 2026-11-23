use ci_core_model::types::{Claim, GitOid, Sha256Digest, UnixSecs, VerifiedClaim};

fn main() {
    let claim = Claim::Image {
        recipe: Sha256Digest::hash_bytes(b"r"),
        manifest: Sha256Digest::hash_bytes(b"m"),
    };
    let _forged = VerifiedClaim {
        claim,
        signing_time: UnixSecs(1),
        signer_sha: GitOid::from_hex("0000000000000000000000000000000000000000").unwrap(),
    };
}
