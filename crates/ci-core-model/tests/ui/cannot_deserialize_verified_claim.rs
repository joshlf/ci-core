use ci_core_model::types::VerifiedClaim;

fn require_deserialize<'de, T: serde::Deserialize<'de>>() {}

fn main() {
    require_deserialize::<VerifiedClaim>();
}
