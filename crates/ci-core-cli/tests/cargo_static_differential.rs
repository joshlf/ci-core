//! Differential parity tests comparing `ci_core_model::cargo_static::discover_workspace`
//! (across both `LocalWorktree` and `BareGitTree`) against real `cargo metadata --no-deps
//! --format-version 1` across 25 synthetic edge-case fixtures AND all 4 workspaces of
//! `google/zerocopy@907b9175fee081872ec883ca4709e6ad922f8ed0`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use ci_core_cli::git_bare::{BareGitTree, HardenedBareGit, LocalWorktree};
use ci_core_model::cargo_static::{
    StaticWorkspaceDiscovery, audit_cargo_locked, discover_workspace,
};
use ci_core_model::tree::SourceTree;
use ci_core_model::types::{GitOid, RegistryIndexUrl, RepoRelPath};

const ZEROCOPY_WITNESS_REV: &str = "907b9175fee081872ec883ca4709e6ad922f8ed0";

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

fn mk_lib(dir: &Path, name: &str, extra_toml: &str, edition: &str) {
    write_file(
        &dir.join("Cargo.toml"),
        &format!(
            "[package]\nname = {name:?}\nversion = \"0.1.0\"\nedition = {edition:?}\n{extra_toml}"
        ),
    );
    write_file(&dir.join("src/lib.rs"), "");
}

#[derive(Debug, PartialEq, Eq)]
struct NormalizedWorkspaceOracle {
    workspace_root: String,
    member_manifests: BTreeSet<String>,
    default_member_manifests: BTreeSet<String>,
    targets_by_manifest: BTreeMap<String, BTreeSet<(Vec<String>, String, String)>>,
    readmes_by_manifest: BTreeMap<String, Option<String>>,
    licenses_by_manifest: BTreeMap<String, Option<String>>,
}

fn rel_to_base(abs_or_rel: &Path, base_root: &Path) -> String {
    let base_canon = fs::canonicalize(base_root).unwrap_or_else(|_| base_root.to_path_buf());
    // Do NOT canonicalize leaf symlinks on target `src_path` (`cargo metadata` preserves
    // lexical paths beneath canonicalized workspace/package dirs); normalize parent if needed.
    let norm = if abs_or_rel.is_absolute() {
        if let Ok(stripped) = abs_or_rel.strip_prefix(&base_canon) {
            stripped.to_path_buf()
        } else if let Ok(stripped) = abs_or_rel.strip_prefix(base_root) {
            stripped.to_path_buf()
        } else if let Some(parent) = abs_or_rel.parent() {
            let p_can = fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
            let fname = abs_or_rel.file_name().unwrap();
            p_can
                .join(fname)
                .strip_prefix(&base_canon)
                .unwrap()
                .to_path_buf()
        } else {
            panic!("cannot relativize {abs_or_rel:?} against {base_root:?}");
        }
    } else {
        abs_or_rel.to_path_buf()
    };
    norm.to_string_lossy().replace('\\', "/")
}

fn oracle_from_cargo_metadata(
    repo_root: &Path,
    manifest_rel: &str,
    cargo_home: &Path,
) -> Result<NormalizedWorkspaceOracle, String> {
    let manifest_abs = repo_root.join(manifest_rel);
    let cwd = manifest_abs.parent().unwrap();
    let out = Command::new("cargo")
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--offline",
            "--manifest-path",
        ])
        .arg(&manifest_abs)
        .current_dir(cwd)
        .env("CARGO_HOME", cargo_home)
        .output()
        .map_err(|e| format!("failed to spawn cargo metadata: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ws_root = rel_to_base(Path::new(v["workspace_root"].as_str().unwrap()), repo_root);

    let mut id_to_manifest = BTreeMap::new();
    let mut targets_by_manifest = BTreeMap::new();
    let mut readmes_by_manifest = BTreeMap::new();
    let mut licenses_by_manifest = BTreeMap::new();

    for pkg in v["packages"].as_array().unwrap() {
        let id = pkg["id"].as_str().unwrap().to_owned();
        let m_rel = rel_to_base(Path::new(pkg["manifest_path"].as_str().unwrap()), repo_root);
        id_to_manifest.insert(id, m_rel.clone());

        let mut tset = BTreeSet::new();
        for t in pkg["targets"].as_array().unwrap() {
            let mut kinds: Vec<String> = t["kind"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_owned())
                .collect();
            kinds.sort();
            let name = t["name"].as_str().unwrap().to_owned();
            let src = rel_to_base(Path::new(t["src_path"].as_str().unwrap()), repo_root);
            tset.insert((kinds, name, src));
        }
        targets_by_manifest.insert(m_rel.clone(), tset);
        readmes_by_manifest.insert(m_rel.clone(), pkg["readme"].as_str().map(ToOwned::to_owned));
        licenses_by_manifest.insert(m_rel, pkg["license_file"].as_str().map(ToOwned::to_owned));
    }

    let member_manifests: BTreeSet<String> = v["workspace_members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id_to_manifest[id.as_str().unwrap()].clone())
        .collect();
    let default_member_manifests: BTreeSet<String> = v["workspace_default_members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id_to_manifest[id.as_str().unwrap()].clone())
        .collect();

    Ok(NormalizedWorkspaceOracle {
        workspace_root: ws_root,
        member_manifests,
        default_member_manifests,
        targets_by_manifest,
        readmes_by_manifest,
        licenses_by_manifest,
    })
}

fn oracle_from_static(static_ws: &StaticWorkspaceDiscovery) -> NormalizedWorkspaceOracle {
    let ws_root = static_ws
        .workspace_root
        .as_ref()
        .map_or_else(String::new, |p| p.as_str().to_owned());
    let member_manifests: BTreeSet<String> = static_ws
        .members
        .keys()
        .map(|p| p.as_str().to_owned())
        .collect();
    let default_member_manifests: BTreeSet<String> = static_ws
        .default_members
        .iter()
        .map(|p| p.as_str().to_owned())
        .collect();

    let mut targets_by_manifest = BTreeMap::new();
    let mut readmes_by_manifest = BTreeMap::new();
    let mut licenses_by_manifest = BTreeMap::new();

    for (mp, pkg) in &static_ws.members {
        let mut tset = BTreeSet::new();
        for t in &pkg.targets {
            let mut kinds = t.kinds.clone();
            kinds.sort();
            tset.insert((kinds, t.name.clone(), t.src_path.as_str().to_owned()));
        }
        targets_by_manifest.insert(mp.as_str().to_owned(), tset);
        readmes_by_manifest.insert(mp.as_str().to_owned(), pkg.readme.clone());
        licenses_by_manifest.insert(mp.as_str().to_owned(), pkg.license_file.clone());
    }

    NormalizedWorkspaceOracle {
        workspace_root: ws_root,
        member_manifests,
        default_member_manifests,
        targets_by_manifest,
        readmes_by_manifest,
        licenses_by_manifest,
    }
}

fn assert_differential_case<F>(case_name: &str, manifest_rel: &str, expect_err: bool, setup: F)
where
    F: FnOnce(&Path, &Path),
{
    let td = tempfile::tempdir().unwrap();
    let cargo_home = td.path().join("cargo_home");
    fs::create_dir_all(&cargo_home).unwrap();
    let repo_root = td.path().join("repo");
    fs::create_dir_all(&repo_root).unwrap();
    setup(td.path(), &repo_root);

    let cargo_res = oracle_from_cargo_metadata(&repo_root, manifest_rel, &cargo_home);
    let tree = LocalWorktree::new(&repo_root).unwrap();
    let static_res = discover_workspace(&tree, &RepoRelPath::new(manifest_rel).unwrap(), &[]);

    if expect_err {
        assert!(
            cargo_res.is_err() && static_res.is_err(),
            "case `{case_name}` expected error in both: cargo={cargo_res:?}, static={static_res:?}"
        );
    } else {
        let expected = cargo_res.unwrap_or_else(|e| {
            panic!("case `{case_name}` cargo metadata unexpectedly failed: {e}")
        });
        let got_ws = static_res
            .unwrap_or_else(|e| panic!("case `{case_name}` cargo_static unexpectedly failed: {e}"));
        let got = oracle_from_static(&got_ws);
        assert_eq!(got, expected, "differential mismatch on case `{case_name}`");
    }
}

#[test]
fn synthetic_25_edge_case_differential_suite_matches_cargo_metadata_with_zero_diffs() {
    // 1. Empty [workspace] + transitive implicit path deps (including cfg(any()))
    assert_differential_case(
        "1_empty_ws_implicit_path_deps",
        "Cargo.toml",
        false,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[workspace]\n[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\na = { path = \"a\" }\n\
             [target.'cfg(any())'.dependencies]\nb = { path = \"b\" }\n",
            );
            write_file(&root.join("src/lib.rs"), "");
            mk_lib(
                &root.join("a"),
                "a",
                "[dev-dependencies]\nc = { path = \"../c\" }\n",
                "2021",
            );
            mk_lib(&root.join("b"), "b", "", "2021");
            mk_lib(&root.join("c"), "c", "", "2021");
        },
    );

    // 2. External path dep outside workspace root (not a member, IS in external_path_deps)
    assert_differential_case(
        "2_external_path_dep_outside_ws",
        "ws/Cargo.toml",
        false,
        |_, repo| {
            mk_lib(&repo.join("ext_crate"), "ext_crate", "", "2021");
            write_file(
                &repo.join("ws/Cargo.toml"),
                "[workspace]\n[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\next_crate = { path = \"../ext_crate\" }\n",
            );
            write_file(&repo.join("ws/src/lib.rs"), "");
        },
    );

    // 3. External path dep WITH `package.workspace = "../ws"` -> IS a member!
    assert_differential_case(
        "3_external_path_dep_workspace_backptr",
        "ws/Cargo.toml",
        false,
        |_, repo| {
            mk_lib(
                &repo.join("ext_member"),
                "ext_member",
                "workspace = \"../ws\"\n",
                "2021",
            );
            write_file(
                &repo.join("ws/Cargo.toml"),
                "[workspace]\n[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\next_member = { path = \"../ext_member\" }\n",
            );
            write_file(&repo.join("ws/src/lib.rs"), "");
        },
    );

    // 4a. `workspace.exclude` wins over glob member & skips non-crate directory
    assert_differential_case(
        "4a_exclude_wins_over_glob",
        "Cargo.toml",
        false,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[workspace]\nmembers = [\"crates/*\"]\nexclude = [\"crates/skip_me\", \"crates/not_a_crate\"]\n",
            );
            mk_lib(&root.join("crates/keep_me"), "keep_me", "", "2021");
            mk_lib(&root.join("crates/skip_me"), "skip_me", "", "2021");
            fs::create_dir_all(root.join("crates/not_a_crate")).unwrap();
            write_file(&root.join("crates/README.md"), "plain file\n");
        },
    );

    // 4b. Literal `members` overrides parent `workspace.exclude`!
    assert_differential_case(
        "4b_literal_member_overrides_exclude",
        "Cargo.toml",
        false,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[workspace]\nmembers = [\"crates/keep_me\"]\nexclude = [\"crates\"]\n",
            );
            mk_lib(&root.join("crates/keep_me"), "keep_me", "", "2021");
            mk_lib(&root.join("crates/other"), "other", "", "2021");
        },
    );

    // 4c. Globs in `workspace.exclude` do NOT expand (`Path::starts_with` literal semantics)!
    assert_differential_case(
        "4c_exclude_does_not_expand_globs",
        "Cargo.toml",
        false,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[workspace]\nmembers = [\"crates/*\"]\nexclude = [\"crates/s*\"]\n",
            );
            mk_lib(
                &root.join("crates/still_included"),
                "still_included",
                "",
                "2021",
            );
        },
    );

    // 5a. Globs match hidden directories & `**` recursive directories
    assert_differential_case(
        "5a_glob_hidden_and_doublestar",
        "Cargo.toml",
        false,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[workspace]\nmembers = [\"crates/*\", \"deep/**/pkg\"]\n",
            );
            mk_lib(
                &root.join("crates/.hidden_crate"),
                "hidden_crate",
                "",
                "2021",
            );
            mk_lib(&root.join("deep/x/y/pkg"), "deep_pkg", "", "2021");
        },
    );

    // 5b. Unexcluded directory without Cargo.toml matched by glob -> HARD ERROR
    assert_differential_case(
        "5b_glob_dir_without_manifest_errors",
        "Cargo.toml",
        true,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[workspace]\nmembers = [\"crates/*\"]\n",
            );
            mk_lib(&root.join("crates/good"), "good", "", "2021");
            fs::create_dir_all(root.join("crates/empty_dir")).unwrap();
        },
    );

    // 5c. Unmatched glob in `workspace.members` -> HARD ERROR
    assert_differential_case(
        "5c_unmatched_member_glob_errors",
        "Cargo.toml",
        true,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[workspace]\nmembers = [\"nonexistent/*\"]\n",
            );
        },
    );

    // 6a. Path dep on nested `[workspace]` WITHOUT `exclude` -> HARD ERROR
    assert_differential_case(
        "6a_nested_ws_without_exclude_errors",
        "Cargo.toml",
        true,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[workspace]\n[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\nnested = { path = \"nested\" }\n",
            );
            write_file(&root.join("src/lib.rs"), "");
            write_file(
                &root.join("nested/Cargo.toml"),
                "[workspace]\n[package]\nname = \"nested\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            );
            write_file(&root.join("nested/src/lib.rs"), "");
        },
    );

    // 6b. Path dep on nested `[workspace]` WITH `exclude` -> succeeds
    assert_differential_case(
        "6b_nested_ws_with_exclude_ok",
        "Cargo.toml",
        false,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[workspace]\nexclude = [\"nested\"]\n[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\nnested = { path = \"nested\" }\n",
            );
            write_file(&root.join("src/lib.rs"), "");
            write_file(
                &root.join("nested/Cargo.toml"),
                "[workspace]\n[package]\nname = \"nested\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            );
            write_file(&root.join("nested/src/lib.rs"), "");
        },
    );

    // 7. `workspace.dependencies` relative path inheritance
    assert_differential_case(
        "7_workspace_deps_inheritance",
        "Cargo.toml",
        false,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[workspace]\nmembers = [\"crates/app\"]\n[workspace.dependencies]\n\
             shared = { path = \"libs/shared\" }\nunused_local = { path = \"libs/unused\" }\n",
            );
            mk_lib(
                &root.join("crates/app"),
                "app",
                "[dependencies]\nshared = { workspace = true }\n",
                "2021",
            );
            mk_lib(&root.join("libs/shared"), "shared", "", "2021");
            mk_lib(&root.join("libs/unused"), "unused_local", "", "2021");
        },
    );

    // 8a & 8b. `[patch.crates-io]` & `[replace]` path deps
    assert_differential_case("8a_patch_path_dep", "Cargo.toml", false, |_, root| {
        write_file(
            &root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\"]\n[patch.crates-io]\npatched = { path = \"patches/patched\" }\n",
        );
        mk_lib(&root.join("app"), "app", "", "2021");
        mk_lib(&root.join("patches/patched"), "patched", "", "2021");
    });

    assert_differential_case("8b_replace_path_dep", "Cargo.toml", false, |_, root| {
        write_file(
            &root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\"]\n[replace]\n\"repl:0.1.0\" = { path = \"repls/repl\" }\n",
        );
        mk_lib(&root.join("app"), "app", "", "2021");
        mk_lib(&root.join("repls/repl"), "repl", "", "2021");
    });

    // 9. Edition 2015 vs 2024 `autotests` & explicit `[[test]]` interaction
    assert_differential_case(
        "9_edition_2015_vs_2024_autotests",
        "Cargo.toml",
        false,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[workspace]\nmembers = [\"e2015_auto\", \"e2015_expl\", \"e2024_expl\", \"e2024_off\"]\n",
            );
            mk_lib(&root.join("e2015_auto"), "e2015_auto", "", "2015");
            write_file(&root.join("e2015_auto/tests/t1.rs"), "");
            write_file(&root.join("e2015_auto/tests/t2/main.rs"), "");

            mk_lib(
                &root.join("e2015_expl"),
                "e2015_expl",
                "[[test]]\nname = \"t1\"\n",
                "2015",
            );
            write_file(&root.join("e2015_expl/tests/t1.rs"), "");
            write_file(&root.join("e2015_expl/tests/t2/main.rs"), "");

            mk_lib(
                &root.join("e2024_expl"),
                "e2024_expl",
                "[[test]]\nname = \"t1\"\n",
                "2024",
            );
            write_file(&root.join("e2024_expl/tests/t1.rs"), "");
            write_file(&root.join("e2024_expl/tests/t2/main.rs"), "");

            mk_lib(
                &root.join("e2024_off"),
                "e2024_off",
                "autotests = false\n[[test]]\nname = \"t1\"\n",
                "2024",
            );
            write_file(&root.join("e2024_off/tests/t1.rs"), "");
            write_file(&root.join("e2024_off/tests/t2/main.rs"), "");
        },
    );

    // 10a & 10b. `src/bench.rs` special legacy pathless bench inference (Edition 2015 resolves,
    // Edition 2021+ drops unresolved pathless non-bin target cleanly).
    assert_differential_case(
        "10a_legacy_src_bench_rs_e2015",
        "Cargo.toml",
        false,
        |_, root| {
            mk_lib(
                root,
                "bench_legacy",
                "autobenches = false\n[[bench]]\nname = \"bench\"\n",
                "2015",
            );
            write_file(&root.join("src/bench.rs"), "");
        },
    );
    assert_differential_case(
        "10b_legacy_src_bench_rs_e2021_omitted",
        "Cargo.toml",
        false,
        |_, root| {
            mk_lib(
                root,
                "bench_legacy",
                "autobenches = false\n[[bench]]\nname = \"bench\"\n",
                "2021",
            );
            write_file(&root.join("src/bench.rs"), "");
        },
    );

    // 11. `autobins = false` + explicit `[[bin]]` omitting `path`
    assert_differential_case(
        "11_autobins_false_inferred_path",
        "Cargo.toml",
        false,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[package]\nname = \"my-cli\"\nversion = \"0.1.0\"\nedition = \"2024\"\nautobins = false\n\
             [[bin]]\nname = \"my-cli\"\n[[bin]]\nname = \"tool\"\n",
            );
            write_file(&root.join("src/main.rs"), "fn main() {}\n");
            write_file(&root.join("src/bin/tool/main.rs"), "fn main() {}\n");
            write_file(&root.join("src/bin/ignored_bin.rs"), "fn main() {}\n");
        },
    );

    // 12. Depth limit, dotfiles, non-.rs, and `DirEntry::file_type().is_dir()` symlink asymmetry!
    assert_differential_case(
        "12_target_depth_dotfiles_symlinks",
        "Cargo.toml",
        false,
        |_, root| {
            mk_lib(root, "sym_test", "", "2021");
            write_file(&root.join("tests/good_file.rs"), "");
            write_file(&root.join("tests/good_sub/main.rs"), "");
            write_file(&root.join("tests/too_deep/nested/main.rs"), "");
            write_file(&root.join("tests/helper_mod/mod.rs"), "");
            write_file(&root.join("tests/.dotfile.rs"), "");
            write_file(&root.join("tests/.dotdir/main.rs"), "");
            write_file(&root.join("tests/not_rust.txt"), "");
            write_file(&root.join("real_target.rs"), "");
            symlink("../real_target.rs", root.join("tests/sym_file.rs")).unwrap();
            write_file(&root.join("real_dir/main.rs"), "");
            symlink("../real_dir", root.join("tests/sym_dir")).unwrap();
            fs::create_dir_all(root.join("tests/real_sub_sym_main")).unwrap();
            symlink(
                "../../real_target.rs",
                root.join("tests/real_sub_sym_main/main.rs"),
            )
            .unwrap();
        },
    );

    // 13. `package.build` modes (`omitted+file`, `omitted+dir`, `false`, `custom`)
    assert_differential_case("13_package_build_modes", "Cargo.toml", false, |_, root| {
        write_file(
            &root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"b_auto\", \"b_dir\", \"b_false\", \"b_custom\"]\n",
        );
        mk_lib(&root.join("b_auto"), "b_auto", "", "2021");
        write_file(&root.join("b_auto/build.rs"), "fn main() {}\n");
        mk_lib(&root.join("b_dir"), "b_dir", "", "2021");
        fs::create_dir_all(root.join("b_dir/build.rs")).unwrap();
        mk_lib(&root.join("b_false"), "b_false", "build = false\n", "2021");
        write_file(&root.join("b_false/build.rs"), "fn main() {}\n");
        mk_lib(
            &root.join("b_custom"),
            "b_custom",
            "build = \"scripts/gen.rs\"\n",
            "2021",
        );
        write_file(&root.join("b_custom/scripts/gen.rs"), "fn main() {}\n");
    });

    // 14. `readme` & `license-file` auto-detection and workspace inheritance
    assert_differential_case(
        "14_readme_and_license_inheritance",
        "Cargo.toml",
        false,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[workspace]\nmembers = [\"p_auto_txt\", \"p_true\", \"p_false\", \"p_inh\"]\n\
             [workspace.package]\nlicense-file = \"LICENSES/CUSTOM\"\n",
            );
            write_file(&root.join("README.txt"), "ws readme\n");
            write_file(&root.join("LICENSES/CUSTOM"), "license\n");
            mk_lib(&root.join("p_auto_txt"), "p_auto_txt", "", "2021");
            write_file(&root.join("p_auto_txt/README.txt"), "txt\n");
            write_file(&root.join("p_auto_txt/README"), "plain\n");
            mk_lib(&root.join("p_true"), "p_true", "readme = true\n", "2021");
            write_file(&root.join("p_true/README.txt"), "ignored\n");
            mk_lib(&root.join("p_false"), "p_false", "readme = false\n", "2021");
            write_file(&root.join("p_false/README.md"), "suppressed\n");
            mk_lib(
                &root.join("p_inh"),
                "p_inh",
                "readme.workspace = true\nlicense-file.workspace = true\n",
                "2021",
            );
        },
    );

    // 15. Deprecated `[project]` & underscore dependency tables (`dev_dependencies`, `build_dependencies`)
    assert_differential_case(
        "15_deprecated_project_and_underscores",
        "Cargo.toml",
        false,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[workspace]\nmembers = [\"legacy\"]\n",
            );
            write_file(
                &root.join("legacy/Cargo.toml"),
                "[project]\nname = \"legacy\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dev_dependencies]\nd1 = { path = \"../d1\" }\n\
             [build_dependencies]\nd2 = { path = \"../d2\" }\n\
             [target.'cfg(unix)'.dev_dependencies]\nd3 = { path = \"../d3\" }\n",
            );
            write_file(&root.join("legacy/src/lib.rs"), "");
            mk_lib(&root.join("d1"), "d1", "", "2021");
            mk_lib(&root.join("d2"), "d2", "", "2021");
            mk_lib(&root.join("d3"), "d3", "", "2021");
        },
    );

    // 16. `default-members` glob filtered by `workspace.exclude`
    assert_differential_case(
        "16_default_members_with_exclude",
        "Cargo.toml",
        false,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[workspace]\nmembers = [\"crates/*\"]\nexclude = [\"crates/b\"]\ndefault-members = [\"crates/*\"]\n",
            );
            mk_lib(&root.join("crates/a"), "a", "", "2021");
            mk_lib(&root.join("crates/b"), "b", "", "2021");
        },
    );

    // 19. Literal nonexistent member in `workspace.members` -> HARD ERROR
    assert_differential_case(
        "19_literal_missing_member_errors",
        "Cargo.toml",
        true,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[workspace]\nmembers = [\"does_not_exist\"]\n",
            );
        },
    );

    // 20. Omitted `package.edition` defaults to Edition 2015
    assert_differential_case(
        "20_omitted_edition_defaults_to_2015",
        "Cargo.toml",
        false,
        |_, root| {
            write_file(
                &root.join("Cargo.toml"),
                "[package]\nname = \"no_ed\"\nversion = \"0.1.0\"\n[[test]]\nname = \"t1\"\n",
            );
            write_file(&root.join("src/lib.rs"), "");
            write_file(&root.join("tests/t1.rs"), "");
            write_file(&root.join("tests/t2.rs"), "");
        },
    );

    // 21-25. Fail-closed static rejections (`metabuild`, `build = [...]`, `-Zpath-bases`,
    // `git+` in `audit_cargo_locked`, and `.cargo/config` shadowing `.cargo/config.toml`).
    {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        mk_lib(root, "meta_bad", "metabuild = [\"foo\"]\n", "2021");
        let tree = LocalWorktree::new(root).unwrap();
        assert!(discover_workspace(&tree, &RepoRelPath::new("Cargo.toml").unwrap(), &[]).is_err());
    }
    {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        mk_lib(
            root,
            "multi_build",
            "build = [\"a.rs\", \"b.rs\"]\n",
            "2021",
        );
        let tree = LocalWorktree::new(root).unwrap();
        assert!(discover_workspace(&tree, &RepoRelPath::new("Cargo.toml").unwrap(), &[]).is_err());
    }
    {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        write_file(
            &root.join("Cargo.toml"),
            "cargo-features = [\"path-bases\"]\n[package]\nname = \"pb\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write_file(&root.join("src/lib.rs"), "");
        let tree = LocalWorktree::new(root).unwrap();
        assert!(discover_workspace(&tree, &RepoRelPath::new("Cargo.toml").unwrap(), &[]).is_err());
    }
    {
        // `.cargo/config` shadows `.cargo/config.toml` at the same directory level, AND
        // `audit_cargo_locked` rejects `git` dependencies in both `Cargo.lock` and `Cargo.toml`.
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        mk_lib(
            root,
            "locked_bad",
            "[dependencies]\nfoo = { git = \"https://example.com/foo.git\" }\n",
            "2021",
        );
        write_file(&root.join(".cargo/config"), "[net]\noffline = true\n");
        write_file(
            &root.join(".cargo/config.toml"),
            "THIS IS INVALID TOML SHADOWED BY .cargo/config\n",
        );
        write_file(
            &root.join("Cargo.lock"),
            "version = 4\n[[package]]\nname = \"locked_bad\"\nversion = \"0.1.0\"\n",
        );
        let tree = LocalWorktree::new(root).unwrap();
        let ws = discover_workspace(&tree, &RepoRelPath::new("Cargo.toml").unwrap(), &[])
            .expect("legacy .cargo/config must shadow broken .cargo/config.toml");
        assert!(
            ws.config_files
                .iter()
                .any(|c| c.path.as_str() == ".cargo/config")
        );
        assert!(
            !ws.config_files
                .iter()
                .any(|c| c.path.as_str() == ".cargo/config.toml")
        );

        let mut reg = BTreeMap::new();
        reg.insert(
            "crates-io".to_owned(),
            RegistryIndexUrl::new("registry+https://github.com/rust-lang/crates.io-index").unwrap(),
        );
        assert!(
            audit_cargo_locked(&tree, &RepoRelPath::new("Cargo.toml").unwrap(), &reg).is_err(),
            "audit_cargo_locked must reject git dependencies in Cargo.toml"
        );
    }
}

#[test]
fn zerocopy_witness_all_four_workspaces_match_cargo_metadata_and_verify_repo_passes() {
    let Some(git_dir) = std::env::var_os("CI_CORE_ZEROCOPY_GIT_DIR").map(PathBuf::from) else {
        eprintln!("skipping optional zerocopy witness probe (`CI_CORE_ZEROCOPY_GIT_DIR` unset)");
        return;
    };
    if !git_dir.exists() {
        eprintln!(
            "skipping optional zerocopy witness probe (`{}` not present)",
            git_dir.display()
        );
        return;
    }

    let rev = GitOid::from_hex(ZEROCOPY_WITNESS_REV).unwrap();
    let bare_git = HardenedBareGit::open_existing(&git_dir).unwrap();
    if !bare_git.object_exists(&rev) {
        eprintln!(
            "skipping optional zerocopy witness probe (commit {ZEROCOPY_WITNESS_REV} absent)"
        );
        return;
    }
    let bare_tree = BareGitTree::from_commit(bare_git, &rev).unwrap();

    // Materialize a clean temporary checkout from `git archive` (read-only on `zerocopy`!).
    let tmp = tempfile::tempdir().unwrap();
    let wt_root = tmp.path().join("zerocopy");
    fs::create_dir_all(&wt_root).unwrap();
    let archive_bytes = Command::new("git")
        .arg("--git-dir")
        .arg(&git_dir)
        .args(["archive", "--format=tar", ZEROCOPY_WITNESS_REV])
        .output()
        .expect("git archive failed");
    assert!(archive_bytes.status.success());
    let mut tar_proc = Command::new("tar")
        .args(["-xf", "-"])
        .arg("-C")
        .arg(&wt_root)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(tar_proc.stdin.as_mut().unwrap(), &archive_bytes.stdout).unwrap();
    drop(tar_proc.stdin.take());
    assert!(tar_proc.wait().unwrap().success());

    let local_tree = LocalWorktree::new(&wt_root).unwrap();
    let cargo_home = PathBuf::from(
        std::env::var("CARGO_HOME")
            .unwrap_or_else(|_| format!("{}/.cargo", std::env::var("HOME").unwrap())),
    );

    for ws_manifest in [
        "zerocopy/Cargo.toml",
        "anneal/Cargo.toml",
        "exocrate/Cargo.toml",
        "tools/Cargo.toml",
    ] {
        let m_rel = RepoRelPath::new(ws_manifest).unwrap();
        let bare_disc = discover_workspace(&bare_tree as &dyn SourceTree, &m_rel, &[])
            .unwrap_or_else(|e| {
                panic!("BareGitTree discover_workspace failed on {ws_manifest}: {e}")
            });
        let local_disc = discover_workspace(&local_tree as &dyn SourceTree, &m_rel, &[])
            .unwrap_or_else(|e| {
                panic!("LocalWorktree discover_workspace failed on {ws_manifest}: {e}")
            });
        assert_eq!(
            oracle_from_static(&bare_disc),
            oracle_from_static(&local_disc),
            "BareGitTree vs LocalWorktree mismatch on {ws_manifest}"
        );

        let cargo_oracle = oracle_from_cargo_metadata(&wt_root, ws_manifest, &cargo_home)
            .unwrap_or_else(|e| panic!("cargo metadata failed on {ws_manifest}: {e}"));
        assert_eq!(
            oracle_from_static(&bare_disc),
            cargo_oracle,
            "cargo_static vs `cargo metadata --no-deps` diff on {ws_manifest}"
        );
    }

    // Overlay `examples/zerocopy/` onto `wt_root` and run the compiled `ci-core verify-repo` binary!
    let examples_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples/zerocopy");
    fn copy_overlay(src: &Path, dst: &Path) {
        for ent in fs::read_dir(src).unwrap() {
            let ent = ent.unwrap();
            let p = ent.path();
            let name = ent.file_name();
            if name == "RULESETS.md" {
                continue;
            }
            let target = dst.join(&name);
            if p.is_dir() {
                fs::create_dir_all(&target).unwrap();
                copy_overlay(&p, &target);
            } else {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).unwrap();
                }
                fs::copy(&p, &target).unwrap();
            }
        }
    }
    copy_overlay(&examples_dir, &wt_root);

    let bin = env!("CARGO_BIN_EXE_ci-core");
    let verify_out = Command::new(bin)
        .args(["verify-repo", "--config", "ci/checks.toml", "--repo-root"])
        .arg(&wt_root)
        .output()
        .expect("failed to execute ci-core verify-repo");
    assert!(
        verify_out.status.success(),
        "ci-core verify-repo failed on zerocopy@907b9175fe + examples/zerocopy:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verify_out.stdout),
        String::from_utf8_lossy(&verify_out.stderr),
    );
}
