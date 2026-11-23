use ci_core_model::types::NonEmptyVec;

fn main() {
    let _empty: NonEmptyVec<u64> = NonEmptyVec(Vec::new());
}
