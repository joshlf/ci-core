use ci_core_model::types::RepoSlug;

fn main() {
    let _bad = RepoSlug {
        canonical: "Google/Zerocopy".to_owned(),
        oci_path: "evil/path".to_owned(),
    };
}
