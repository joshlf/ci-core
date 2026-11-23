//! Zero-execution static Cargo workspace, target, path-dependency, config, and
//! `cargo_locked` closure analyzer over `SourceTree`.
//!
//! Matches `rust-lang/cargo@930a674da900a73c1dfbe16be62c42e75bdfdfc0` across
//! Editions 2015–2024 without invoking `cargo`, `rustc`, or `build.rs`.

use std::collections::{BTreeMap, BTreeSet};

use globset::GlobBuilder;
use thiserror::Error;

use crate::tree::{EntryKind, SourceTree, TreeEntry, TreeError, resolve_in_tree};
use crate::types::{RegistryIndexUrl, RepoRelPath};

const DEFAULT_README_FILES: [&str; 3] = ["README.md", "README.txt", "README"];

/// Errors returned during static Cargo workspace discovery or `cargo_locked`
/// auditing.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CargoStaticError {
    /// Underlying `SourceTree` failure.
    #[error(transparent)]
    Tree(#[from] TreeError),
    /// Invalid UTF-8 or TOML syntax in a `Cargo.toml`, `Cargo.lock`, or
    /// `.cargo/config(.toml)` file.
    #[error("failed to parse `{path}`: {reason}")]
    Parse {
        /// File path inside the repository.
        path: String,
        /// Parse error message.
        reason: String,
    },
    /// Invalid Cargo workspace/manifest structure or unsupported nightly feature.
    #[error("cargo manifest error in `{path}`: {reason}")]
    Manifest {
        /// Manifest or config path.
        path: String,
        /// Structural validation failure.
        reason: String,
    },
    /// A relative path inside a manifest or `.cargo/config(.toml)` escaped the
    /// repository root.
    #[error("path `{raw}` from `{origin}` escapes repository root")]
    PathEscapesRepo {
        /// Origin manifest or config path.
        origin: String,
        /// Escaping relative path string.
        raw: String,
    },
    /// Dual static `cargo_locked` audit failure.
    #[error("cargo_locked violation in `{path}`: {reason}")]
    LockedAudit {
        /// Violating `Cargo.lock` or `Cargo.toml` path.
        path: String,
        /// Explanation of the forbidden source or dependency key.
        reason: String,
    },
}

/// Statically inferred or explicit Cargo target (`[lib]`, `[[bin]]`,
/// `[[example]]`, `[[test]]`, `[[bench]]`, or `custom-build`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticCargoTarget {
    /// Sorted target kinds (`"lib"`, `"proc-macro"`, `"bin"`, `"test"`, etc.).
    pub kinds: Vec<String>,
    /// Target name.
    pub name: String,
    /// Normalized repository-relative path to the target root `.rs` file.
    pub src_path: RepoRelPath,
}

/// Statically resolved local `path = "..."` dependency.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StaticPathDep {
    /// Actual target package name (`package` override if renamed, else key).
    pub name: String,
    /// TOML dependency key when `package = "..."` renamed the dependency.
    pub rename: Option<String>,
    /// `None` (normal), `Some("dev")`, or `Some("build")`.
    pub kind: Option<String>,
    /// Target triple or `cfg(...)` key from `[target.<k>.*]`.
    pub target: Option<String>,
    /// Normalized repository-relative directory of the dependency crate
    /// (`None` denotes the repository root directory `""`).
    pub path: Option<RepoRelPath>,
}

/// Statically parsed Cargo package (`Cargo.toml`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticPackage {
    /// Package name.
    pub name: String,
    /// Resolved Rust edition (`"2015"`, `"2018"`, `"2021"`, or `"2024"`).
    pub edition: String,
    /// Repository-relative `Cargo.toml` path.
    pub manifest_path: RepoRelPath,
    /// Package root directory (`None` when `manifest_path == "Cargo.toml"`).
    pub package_root: Option<RepoRelPath>,
    /// Normalized `readme` relative to `package_root` (`cargo metadata` form).
    pub readme: Option<String>,
    /// Normalized `license-file` relative to `package_root`.
    pub license_file: Option<String>,
    /// Resolved `readme` inside the repository if inside repo bounds.
    pub readme_repo_path: Option<RepoRelPath>,
    /// Resolved `license-file` inside the repository if inside repo bounds.
    pub license_file_repo_path: Option<RepoRelPath>,
    /// Discovered build/test/bench/example/lib/bin targets.
    pub targets: Vec<StaticCargoTarget>,
    /// Local `path` dependencies across all dependency tables.
    pub path_deps: Vec<StaticPathDep>,
    /// Whether `[workspace]` is present in this manifest.
    pub has_workspace_table: bool,
}

/// Statically discovered `.cargo/config(.toml)` or included `.toml` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticCargoConfigFile {
    /// Repository-relative path of the config or included `.toml` file.
    pub path: RepoRelPath,
    /// Whether the target file currently exists in `tree` (`false` only for
    /// absent `{ path = "...", optional = true }` `include` targets, which TCB
    /// still guards against creation/modification).
    pub exists: bool,
    /// Resolved `[source.*].directory` trees (`None` = repo root `""`).
    pub vendored_dirs: Vec<Option<RepoRelPath>>,
    /// Resolved `[source.*].local-registry` trees.
    pub local_registries: Vec<Option<RepoRelPath>>,
    /// Resolved `[patch.*]` crate directories.
    pub patch_paths: Vec<Option<RepoRelPath>>,
    /// Resolved `[resolver].lockfile-path` override.
    pub lockfile_path: Option<RepoRelPath>,
}

/// Complete static workspace discovery result matching `cargo metadata --no-deps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticWorkspaceDiscovery {
    /// Workspace root directory (`None` = repository root `""`).
    pub workspace_root: Option<RepoRelPath>,
    /// Workspace root `Cargo.toml` path.
    pub root_manifest: RepoRelPath,
    /// `true` when `root_manifest` has `[workspace]` and no `[package]`.
    pub is_virtual: bool,
    /// Workspace member packages keyed by `manifest_path`.
    pub members: BTreeMap<RepoRelPath, StaticPackage>,
    /// Default workspace member `manifest_path`s.
    pub default_members: Vec<RepoRelPath>,
    /// Transitive non-member path dependencies (`[patch]`, `[replace]`, and
    /// external `path` deps without `package.workspace` back-pointer).
    pub external_path_deps: BTreeMap<RepoRelPath, StaticPackage>,
    /// Resolved `[patch]` crate directories.
    pub patch_path_deps: Vec<Option<RepoRelPath>>,
    /// Resolved `[replace]` crate directories.
    pub replace_path_deps: Vec<Option<RepoRelPath>>,
    /// Effective `Cargo.lock` path.
    pub lockfile_path: RepoRelPath,
    /// Whether `lockfile_path` exists as a regular file in `tree`.
    pub lockfile_exists: bool,
    /// Discovered `.cargo/config(.toml)` and recursive `include` files.
    pub config_files: Vec<StaticCargoConfigFile>,
    /// Discovered `rust-toolchain(.toml)` files along upward walks.
    pub rust_toolchain_files: BTreeSet<RepoRelPath>,
}

impl StaticWorkspaceDiscovery {
    /// Returns every discovered crate root directory (`None` = repo root `""`)
    /// across workspace root, members, external path deps, patches, and
    /// replaces.
    pub fn all_crate_dirs(&self) -> BTreeSet<Option<RepoRelPath>> {
        let mut dirs = BTreeSet::new();
        dirs.insert(self.workspace_root.clone());
        for pkg in self
            .members
            .values()
            .chain(self.external_path_deps.values())
        {
            dirs.insert(pkg.package_root.clone());
        }
        for p in self
            .patch_path_deps
            .iter()
            .chain(self.replace_path_deps.iter())
        {
            dirs.insert(p.clone());
        }
        dirs
    }
}

/// Materializable manifest + 0-byte target stub tree produced by
/// `audit_cargo_locked`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoLockedFetchPlan {
    /// Workspace root `Cargo.toml` path passed to `--manifest-path`.
    pub workspace_manifest: RepoRelPath,
    /// Validated `Cargo.lock` path and raw bytes.
    pub lockfile: (RepoRelPath, Vec<u8>),
    /// Exact `Cargo.toml` manifests (`manifest_path -> raw_bytes`).
    pub manifests: BTreeMap<RepoRelPath, Vec<u8>>,
    /// Sorted 0-byte empty stub paths for every statically discovered target.
    pub target_stubs: BTreeSet<RepoRelPath>,
}

/// Joins `rel` onto `base` (`None` = repo root `""`) and normalizes `.` and
/// `..` lexically within the repository root (`Ok(None)` = repo root `""`).
pub fn resolve_repo_rel(
    base: Option<&RepoRelPath>,
    rel: &str,
    origin: &str,
) -> Result<Option<RepoRelPath>, CargoStaticError> {
    if rel.starts_with('/') || rel.contains('\0') || rel.contains('\\') {
        return Err(CargoStaticError::PathEscapesRepo {
            origin: origin.to_owned(),
            raw: rel.to_owned(),
        });
    }
    let mut parts: Vec<String> = match base {
        Some(b) => b.as_str().split('/').map(str::to_owned).collect(),
        None => Vec::new(),
    };
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            if parts.pop().is_none() {
                return Err(CargoStaticError::PathEscapesRepo {
                    origin: origin.to_owned(),
                    raw: rel.to_owned(),
                });
            }
        } else {
            parts.push(seg.to_owned());
        }
    }
    if parts.is_empty() {
        Ok(None)
    } else {
        RepoRelPath::new(&parts.join("/"))
            .map(Some)
            .map_err(|e| CargoStaticError::Manifest {
                path: origin.to_owned(),
                reason: e.to_string(),
            })
    }
}

fn manifest_in_dir(dir: Option<&RepoRelPath>) -> RepoRelPath {
    match dir {
        None => RepoRelPath::new("Cargo.toml").expect("static literal"),
        Some(d) => d
            .join_segment("Cargo.toml")
            .expect("valid Cargo.toml segment"),
    }
}

fn dir_starts_with(path: Option<&RepoRelPath>, prefix: Option<&RepoRelPath>) -> bool {
    match (path, prefix) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(p), Some(pre)) => pre.is_prefix_of(p),
    }
}

fn manifest_starts_with_dir(manifest: &RepoRelPath, prefix: Option<&RepoRelPath>) -> bool {
    match prefix {
        None => true,
        Some(pre) => pre.is_prefix_of(manifest),
    }
}

fn diff_repo_dirs(from_dir: Option<&RepoRelPath>, to_path: Option<&RepoRelPath>) -> String {
    let from_parts: Vec<&str> = from_dir
        .map(|d| d.as_str().split('/').collect())
        .unwrap_or_default();
    let to_parts: Vec<&str> = to_path
        .map(|d| d.as_str().split('/').collect())
        .unwrap_or_default();
    let mut common = 0usize;
    while common < from_parts.len()
        && common < to_parts.len()
        && from_parts[common] == to_parts[common]
    {
        common += 1;
    }
    let mut out: Vec<&str> = vec![".."; from_parts.len() - common];
    out.extend_from_slice(&to_parts[common..]);
    if out.is_empty() {
        ".".to_owned()
    } else {
        out.join("/")
    }
}

fn tree_follows_to_file(tree: &dyn SourceTree, path: &RepoRelPath) -> bool {
    match tree.entry(path) {
        Ok(Some(TreeEntry::Regular { .. })) => true,
        Ok(Some(TreeEntry::Symlink { .. })) => {
            matches!(
                resolve_in_tree(tree, path),
                Ok((_, _, Some(EntryKind::File)))
            )
        }
        _ => false,
    }
}

fn tree_follows_to_dir(tree: &dyn SourceTree, dir: Option<&RepoRelPath>) -> bool {
    match dir {
        None => true,
        Some(d) => match tree.kind_of(d) {
            Ok(Some(EntryKind::Dir)) => true,
            Ok(Some(EntryKind::Symlink)) => {
                matches!(resolve_in_tree(tree, d), Ok((_, _, Some(EntryKind::Dir))))
            }
            _ => false,
        },
    }
}

fn tree_exists_following_symlinks(tree: &dyn SourceTree, path: &RepoRelPath) -> bool {
    match tree.kind_of(path) {
        Ok(Some(EntryKind::File | EntryKind::Dir)) => true,
        Ok(Some(EntryKind::Symlink)) => {
            matches!(
                resolve_in_tree(tree, path),
                Ok((_, _, Some(EntryKind::File | EntryKind::Dir)))
            )
        }
        _ => false,
    }
}

fn read_toml_table(
    tree: &dyn SourceTree,
    path: &RepoRelPath,
) -> Result<toml::Table, CargoStaticError> {
    let Some(TreeEntry::Regular { .. }) = tree.entry(path)? else {
        // Cargo follows symlinks for manifests if inside closure, so resolve if symlink.
        if matches!(tree.entry(path)?, Some(TreeEntry::Symlink { .. })) {
            let (_, resolved, kind) = resolve_in_tree(tree, path)?;
            if kind != Some(EntryKind::File) {
                return Err(CargoStaticError::Manifest {
                    path: path.to_string(),
                    reason: "manifest does not exist as a regular file".to_owned(),
                });
            }
            let bytes = tree.read_blob(&resolved)?;
            let text = std::str::from_utf8(&bytes).map_err(|e| CargoStaticError::Parse {
                path: path.to_string(),
                reason: e.to_string(),
            })?;
            return toml::from_str(text).map_err(|e| CargoStaticError::Parse {
                path: path.to_string(),
                reason: e.to_string(),
            });
        }
        return Err(CargoStaticError::Manifest {
            path: path.to_string(),
            reason: "file does not exist".to_owned(),
        });
    };
    let bytes = tree.read_blob(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|e| CargoStaticError::Parse {
        path: path.to_string(),
        reason: e.to_string(),
    })?;
    toml::from_str(text).map_err(|e| CargoStaticError::Parse {
        path: path.to_string(),
        reason: e.to_string(),
    })
}

fn expand_member_glob_in_tree(
    tree: &dyn SourceTree,
    root_dir: Option<&RepoRelPath>,
    pattern: &str,
    origin: &str,
) -> Result<Vec<Option<RepoRelPath>>, CargoStaticError> {
    if pattern.starts_with('/') || pattern.contains('\0') || pattern.contains('\\') {
        return Err(CargoStaticError::Manifest {
            path: origin.to_owned(),
            reason: format!("invalid member glob {pattern:?}"),
        });
    }
    let comps: Vec<&str> = pattern
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    let mut results: BTreeSet<Option<RepoRelPath>> = BTreeSet::new();

    fn walk(
        tree: &dyn SourceTree,
        cur: Option<RepoRelPath>,
        comps: &[&str],
        idx: usize,
        origin: &str,
        results: &mut BTreeSet<Option<RepoRelPath>>,
    ) -> Result<(), CargoStaticError> {
        if idx == comps.len() {
            let exists = match &cur {
                None => true,
                Some(p) => tree.kind_of(p)?.is_some(),
            };
            if exists {
                results.insert(cur);
            }
            return Ok(());
        }
        let comp = comps[idx];
        if comp == ".." {
            let parent = match &cur {
                Some(p) => p.parent(),
                None => {
                    return Err(CargoStaticError::PathEscapesRepo {
                        origin: origin.to_owned(),
                        raw: "..".to_owned(),
                    });
                }
            };
            return walk(tree, parent, comps, idx + 1, origin, results);
        }
        if comp == "**" {
            walk(tree, cur.clone(), comps, idx + 1, origin, results)?;
            if tree_follows_to_dir(tree, cur.as_ref()) {
                let list_target = match &cur {
                    None => None,
                    Some(p) if tree.kind_of(p)? == Some(EntryKind::Symlink) => {
                        let (_, r, _) = resolve_in_tree(tree, p)?;
                        Some(r)
                    }
                    Some(p) => Some(p.clone()),
                };
                for (name, kind) in tree.list_dir(list_target.as_ref())? {
                    if name == ".git" {
                        continue;
                    }
                    let child = match &cur {
                        None => RepoRelPath::new(&name).ok(),
                        Some(c) => c.join_segment(&name).ok(),
                    };
                    let Some(child_p) = child else { continue };
                    let is_dir = kind == EntryKind::Dir
                        || (kind == EntryKind::Symlink
                            && tree_follows_to_dir(tree, Some(&child_p)));
                    if is_dir {
                        walk(tree, Some(child_p), comps, idx, origin, results)?;
                    }
                }
            }
        } else if comp.contains('*') || comp.contains('?') || comp.contains('[') {
            if !tree_follows_to_dir(tree, cur.as_ref()) {
                return Ok(());
            }
            let pat = GlobBuilder::new(comp)
                .literal_separator(true)
                .backslash_escape(false)
                .build()
                .map_err(|e| CargoStaticError::Manifest {
                    path: origin.to_owned(),
                    reason: format!("invalid glob `{comp}`: {e}"),
                })?
                .compile_matcher();
            let list_target = match &cur {
                None => None,
                Some(p) if tree.kind_of(p)? == Some(EntryKind::Symlink) => {
                    let (_, r, _) = resolve_in_tree(tree, p)?;
                    Some(r)
                }
                Some(p) => Some(p.clone()),
            };
            for (name, _) in tree.list_dir(list_target.as_ref())? {
                if name == ".git" {
                    continue;
                }
                if pat.is_match(&name) {
                    let child = match &cur {
                        None => RepoRelPath::new(&name).ok(),
                        Some(c) => c.join_segment(&name).ok(),
                    };
                    if let Some(child_p) = child {
                        walk(tree, Some(child_p), comps, idx + 1, origin, results)?;
                    }
                }
            }
        } else {
            let nxt = resolve_repo_rel(cur.as_ref(), comp, origin)?;
            if idx + 1 == comps.len() {
                let exists = match &nxt {
                    None => true,
                    Some(p) => tree.kind_of(p)?.is_some(),
                };
                if exists {
                    results.insert(nxt);
                }
            } else if tree_follows_to_dir(tree, nxt.as_ref()) {
                walk(tree, nxt, comps, idx + 1, origin, results)?;
            }
        }
        Ok(())
    }

    walk(tree, root_dir.cloned(), &comps, 0, origin, &mut results)?;
    Ok(results.into_iter().collect())
}

/// Discovers `.cargo/config` (shadowing `.cargo/config.toml` in the same
/// directory) and recursive Cargo 1.82+ `include` targets walking upward from
/// `start_dir` (`None` = repository root `""`) up to the repository root `""`
/// inclusive.
pub fn discover_cargo_configs_from_dir(
    tree: &dyn SourceTree,
    start_dir: Option<&RepoRelPath>,
) -> Result<Vec<StaticCargoConfigFile>, CargoStaticError> {
    let mut top_configs: Vec<RepoRelPath> = Vec::new();
    let mut cur = start_dir.cloned();
    loop {
        let cargo_dir = match &cur {
            None => RepoRelPath::new(".cargo").expect("static"),
            Some(d) => d.join_segment(".cargo").expect("static"),
        };
        let legacy = cargo_dir.join_segment("config").expect("static");
        let modern = cargo_dir.join_segment("config.toml").expect("static");
        if tree.kind_of(&legacy)?.is_some() {
            top_configs.push(legacy);
        } else if tree.kind_of(&modern)?.is_some() {
            top_configs.push(modern);
        }
        match cur {
            None => break,
            Some(d) => cur = d.parent(),
        }
    }

    let mut ordered = Vec::new();
    let mut visiting = BTreeSet::new();
    let mut seen = BTreeSet::new();

    fn load_config_recursive(
        tree: &dyn SourceTree,
        cfg_path: RepoRelPath,
        optional: bool,
        visiting: &mut BTreeSet<RepoRelPath>,
        seen: &mut BTreeSet<RepoRelPath>,
        ordered: &mut Vec<StaticCargoConfigFile>,
    ) -> Result<(), CargoStaticError> {
        if visiting.contains(&cfg_path) {
            return Err(CargoStaticError::Manifest {
                path: cfg_path.to_string(),
                reason: "cycle detected in `.cargo/config` `include` chain".to_owned(),
            });
        }
        if tree.kind_of(&cfg_path)?.is_none() {
            if optional {
                if seen.insert(cfg_path.clone()) {
                    ordered.push(StaticCargoConfigFile {
                        path: cfg_path,
                        exists: false,
                        vendored_dirs: Vec::new(),
                        local_registries: Vec::new(),
                        patch_paths: Vec::new(),
                        lockfile_path: None,
                    });
                }
                return Ok(());
            }
            return Err(CargoStaticError::Manifest {
                path: cfg_path.to_string(),
                reason: "non-optional `.cargo/config` include target does not exist".to_owned(),
            });
        }
        if !seen.insert(cfg_path.clone()) {
            return Ok(());
        }
        visiting.insert(cfg_path.clone());

        let tbl = read_toml_table(tree, &cfg_path)?;
        // `Definition::root` for `.cargo/config(.toml)` is two levels up
        // (`cfg_path.parent().parent()`).
        let cfg_parent = cfg_path.parent();
        let def_root = cfg_parent.as_ref().and_then(RepoRelPath::parent);
        let origin = cfg_path.as_str();

        let mut vendored_dirs = Vec::new();
        let mut local_registries = Vec::new();
        if let Some(sources) = tbl.get("source").and_then(toml::Value::as_table) {
            for sdef in sources.values() {
                if let Some(stbl) = sdef.as_table() {
                    if let Some(dir_s) = stbl.get("directory").and_then(toml::Value::as_str) {
                        vendored_dirs.push(resolve_repo_rel(def_root.as_ref(), dir_s, origin)?);
                    }
                    if let Some(lr_s) = stbl.get("local-registry").and_then(toml::Value::as_str) {
                        local_registries.push(resolve_repo_rel(def_root.as_ref(), lr_s, origin)?);
                    }
                }
            }
        }

        let mut patch_paths = Vec::new();
        if let Some(patches) = tbl.get("patch").and_then(toml::Value::as_table) {
            for pmap in patches.values() {
                if let Some(ptbl) = pmap.as_table() {
                    for pdep in ptbl.values() {
                        if let Some(dtbl) = pdep.as_table()
                            && let Some(ps) = dtbl.get("path").and_then(toml::Value::as_str)
                        {
                            patch_paths.push(resolve_repo_rel(def_root.as_ref(), ps, origin)?);
                        }
                    }
                }
            }
        }

        let mut lockfile_path = None;
        if let Some(res_tbl) = tbl.get("resolver").and_then(toml::Value::as_table)
            && let Some(lp) = res_tbl.get("lockfile-path").and_then(toml::Value::as_str)
        {
            let resolved = resolve_repo_rel(def_root.as_ref(), lp, origin)?.ok_or_else(|| {
                CargoStaticError::Manifest {
                    path: cfg_path.to_string(),
                    reason: "resolver.lockfile-path must end in Cargo.lock".to_owned(),
                }
            })?;
            lockfile_path = Some(resolved);
        }

        if tbl.contains_key("path-bases") {
            return Err(CargoStaticError::Manifest {
                path: cfg_path.to_string(),
                reason: "unstable Cargo `[path-bases]` is unsupported".to_owned(),
            });
        }

        let mut includes: Vec<(RepoRelPath, bool)> = Vec::new();
        if let Some(inc_val) = tbl.get("include") {
            let items: Vec<&toml::Value> = match inc_val {
                toml::Value::String(_) => vec![inc_val],
                toml::Value::Array(arr) => arr.iter().collect(),
                _ => {
                    return Err(CargoStaticError::Manifest {
                        path: cfg_path.to_string(),
                        reason: "invalid `.cargo/config` `include` type".to_owned(),
                    });
                }
            };
            for item in items {
                let (rel_s, opt) = match item {
                    toml::Value::String(s) => (s.as_str(), false),
                    toml::Value::Table(t) => {
                        let p = t.get("path").and_then(toml::Value::as_str).ok_or_else(|| {
                            CargoStaticError::Manifest {
                                path: cfg_path.to_string(),
                                reason: "`include` table entry missing `path`".to_owned(),
                            }
                        })?;
                        let opt = t
                            .get("optional")
                            .and_then(toml::Value::as_bool)
                            .unwrap_or(false);
                        (p, opt)
                    }
                    _ => {
                        return Err(CargoStaticError::Manifest {
                            path: cfg_path.to_string(),
                            reason: "invalid `include` entry".to_owned(),
                        });
                    }
                };
                if !rel_s.ends_with(".toml")
                    || rel_s.contains('*')
                    || rel_s.contains('?')
                    || rel_s.contains('[')
                {
                    return Err(CargoStaticError::Manifest {
                        path: cfg_path.to_string(),
                        reason: format!(
                            "`include` target {rel_s:?} must be a non-glob `.toml` path"
                        ),
                    });
                }
                let inc_target =
                    resolve_repo_rel(cfg_parent.as_ref(), rel_s, origin)?.ok_or_else(|| {
                        CargoStaticError::Manifest {
                            path: cfg_path.to_string(),
                            reason: format!("invalid `include` target {rel_s:?}"),
                        }
                    })?;
                includes.push((inc_target, opt));
            }
        }

        ordered.push(StaticCargoConfigFile {
            path: cfg_path.clone(),
            exists: true,
            vendored_dirs,
            local_registries,
            patch_paths,
            lockfile_path,
        });

        for (inc_target, opt) in includes {
            load_config_recursive(tree, inc_target, opt, visiting, seen, ordered)?;
        }
        visiting.remove(&cfg_path);
        Ok(())
    }

    for top in top_configs {
        load_config_recursive(tree, top, false, &mut visiting, &mut seen, &mut ordered)?;
    }
    Ok(ordered)
}

/// Discovers `rust-toolchain` (shadowing `rust-toolchain.toml` in the same
/// directory) walking upward from `start_dir` (`None` = repo root `""`) up to
/// the repository root `""` inclusive.
pub fn discover_rust_toolchains_from_dir(
    tree: &dyn SourceTree,
    start_dir: Option<&RepoRelPath>,
) -> Result<Vec<RepoRelPath>, CargoStaticError> {
    let mut found = Vec::new();
    let mut cur = start_dir.cloned();
    loop {
        let legacy = match &cur {
            None => RepoRelPath::new("rust-toolchain").expect("static"),
            Some(d) => d.join_segment("rust-toolchain").expect("static"),
        };
        let modern = match &cur {
            None => RepoRelPath::new("rust-toolchain.toml").expect("static"),
            Some(d) => d.join_segment("rust-toolchain.toml").expect("static"),
        };
        if tree_follows_to_file(tree, &legacy) || tree.kind_of(&legacy)?.is_some() {
            found.push(legacy);
        } else if tree_follows_to_file(tree, &modern) || tree.kind_of(&modern)?.is_some() {
            found.push(modern);
        }
        match cur {
            None => break,
            Some(d) => cur = d.parent(),
        }
    }
    Ok(found)
}

struct Analyzer<'a> {
    tree: &'a dyn SourceTree,
    raw_cache: BTreeMap<RepoRelPath, toml::Table>,
}

impl<'a> Analyzer<'a> {
    fn new(tree: &'a dyn SourceTree) -> Self {
        Self {
            tree,
            raw_cache: BTreeMap::new(),
        }
    }

    fn load_raw(&mut self, manifest_path: &RepoRelPath) -> Result<toml::Table, CargoStaticError> {
        if let Some(cached) = self.raw_cache.get(manifest_path) {
            return Ok(cached.clone());
        }
        let tbl = read_toml_table(self.tree, manifest_path)?;
        if let Some(cf) = tbl.get("cargo-features").and_then(toml::Value::as_array) {
            for feat in cf {
                if let Some(s) = feat.as_str()
                    && matches!(s, "path-bases" | "multiple-build-scripts")
                {
                    return Err(CargoStaticError::Manifest {
                        path: manifest_path.to_string(),
                        reason: format!("unstable `cargo-features` `{s}` is unsupported"),
                    });
                }
            }
        }
        self.raw_cache.insert(manifest_path.clone(), tbl.clone());
        Ok(tbl)
    }

    fn get_pkg_table(
        raw: &toml::Table,
        manifest_path: &RepoRelPath,
    ) -> Result<Option<(toml::Table, bool)>, CargoStaticError> {
        if let Some(p) = raw.get("package").and_then(toml::Value::as_table) {
            return Ok(Some((p.clone(), false)));
        }
        if let Some(p) = raw.get("project").and_then(toml::Value::as_table) {
            return Ok(Some((p.clone(), true)));
        }
        if raw.contains_key("package") || raw.contains_key("project") {
            return Err(CargoStaticError::Manifest {
                path: manifest_path.to_string(),
                reason: "`[package]` must be a TOML table".to_owned(),
            });
        }
        Ok(None)
    }

    fn is_excluded(
        root_dir: Option<&RepoRelPath>,
        ws_table: &toml::Table,
        manifest_path: &RepoRelPath,
        origin: &str,
    ) -> Result<bool, CargoStaticError> {
        let mut excluded = false;
        if let Some(ex_arr) = ws_table.get("exclude").and_then(toml::Value::as_array) {
            for ex_val in ex_arr {
                if let Some(ex_s) = ex_val.as_str() {
                    let ex_dir = resolve_repo_rel(root_dir, ex_s, origin)?;
                    if manifest_starts_with_dir(manifest_path, ex_dir.as_ref()) {
                        excluded = true;
                        break;
                    }
                }
            }
        }
        let mut explicit_member = false;
        if let Some(mem_arr) = ws_table.get("members").and_then(toml::Value::as_array) {
            for mem_val in mem_arr {
                if let Some(mem_s) = mem_val.as_str() {
                    // Literal `Path::starts_with` without glob expansion:
                    // literal `members` override `exclude`, globs do not.
                    if !mem_s.contains('*')
                        && !mem_s.contains('?')
                        && !mem_s.contains('[')
                        && let Ok(mem_dir) = resolve_repo_rel(root_dir, mem_s, origin)
                        && manifest_starts_with_dir(manifest_path, mem_dir.as_ref())
                    {
                        explicit_member = true;
                        break;
                    }
                }
            }
        }
        Ok(!explicit_member && excluded)
    }

    fn get_ws_root_from_manifest(
        &mut self,
        self_path: &RepoRelPath,
        look_from: &RepoRelPath,
    ) -> Result<Option<RepoRelPath>, CargoStaticError> {
        let raw = self.load_raw(self_path)?;
        let ws = raw.get("workspace").and_then(toml::Value::as_table);
        let pkg = Self::get_pkg_table(&raw, self_path)?;
        let pkg_ws = pkg
            .as_ref()
            .and_then(|(p, _)| p.get("workspace"))
            .and_then(toml::Value::as_str);
        if ws.is_some() && pkg_ws.is_some() {
            return Err(CargoStaticError::Manifest {
                path: self_path.to_string(),
                reason: "cannot specify both `[workspace]` and `package.workspace`".to_owned(),
            });
        }
        if let Some(ws_tbl) = ws {
            let root_dir = self_path.parent();
            if !Self::is_excluded(root_dir.as_ref(), ws_tbl, look_from, self_path.as_str())? {
                return Ok(Some(self_path.clone()));
            }
            return Ok(None);
        }
        if let Some(rel_ws) = pkg_ws {
            let ws_dir = resolve_repo_rel(self_path.parent().as_ref(), rel_ws, self_path.as_str())?;
            return Ok(Some(manifest_in_dir(ws_dir.as_ref())));
        }
        Ok(None)
    }

    fn find_workspace_root(
        &mut self,
        manifest_path: &RepoRelPath,
    ) -> Result<Option<RepoRelPath>, CargoStaticError> {
        if let Some(direct) = self.get_ws_root_from_manifest(manifest_path, manifest_path)? {
            return Ok(Some(direct));
        }
        // Walk ancestors starting at `manifest_path.parent().parent()` up to
        // repo root `""`.
        let Some(pkg_dir) = manifest_path.parent() else {
            return Ok(None);
        };
        let mut cur = pkg_dir.parent();
        loop {
            if let Some(ref c) = cur
                && c.as_str().ends_with("target/package")
            {
                break;
            }
            let cand = manifest_in_dir(cur.as_ref());
            if self.tree.kind_of(&cand)?.is_some()
                && let Some(found) = self.get_ws_root_from_manifest(&cand, manifest_path)?
            {
                return Ok(Some(found));
            }
            match cur {
                None => break,
                Some(c) => cur = c.parent(),
            }
        }
        Ok(None)
    }

    fn expand_members_paths(
        &self,
        root_dir: Option<&RepoRelPath>,
        globs: &[String],
        origin: &str,
    ) -> Result<Vec<(Option<RepoRelPath>, bool)>, CargoStaticError> {
        let mut out = Vec::new();
        for g in globs {
            let is_glob_syntax = g.contains('*') || g.contains('?') || g.contains('[');
            let expanded = expand_member_glob_in_tree(self.tree, root_dir, g, origin)?;
            if expanded.is_empty() {
                if is_glob_syntax {
                    return Err(CargoStaticError::Manifest {
                        path: origin.to_owned(),
                        reason: format!("workspace member glob {g:?} matched no directories"),
                    });
                }
                let literal = resolve_repo_rel(root_dir, g, origin)?;
                out.push((literal, false));
            } else {
                for ep in expanded {
                    if tree_follows_to_dir(self.tree, ep.as_ref()) {
                        out.push((ep, is_glob_syntax));
                    } else if !is_glob_syntax {
                        out.push((ep, false));
                    }
                }
            }
        }
        Ok(out)
    }

    fn infer_from_directory(
        &self,
        package_root: Option<&RepoRelPath>,
        subdir: &str,
        origin: &str,
    ) -> Result<Vec<(String, String)>, CargoStaticError> {
        let Some(dir_path) = resolve_repo_rel(package_root, subdir, origin)? else {
            return Ok(Vec::new());
        };
        if !tree_follows_to_dir(self.tree, Some(&dir_path)) {
            return Ok(Vec::new());
        }
        let list_target = if self.tree.kind_of(&dir_path)? == Some(EntryKind::Symlink) {
            let (_, r, _) = resolve_in_tree(self.tree, &dir_path)?;
            r
        } else {
            dir_path.clone()
        };
        let mut out = Vec::new();
        for (name, kind) in self.tree.list_dir(Some(&list_target))? {
            if name.starts_with('.') {
                continue;
            }
            // Cargo `infer_any` uses `DirEntry::file_type().is_dir()` (does NOT
            // follow symlinks on subdirectories), while `.rs` symlinks fall
            // into the `else if` branch and `sub/main.rs.exists()` DOES follow
            // symlinks.
            if kind == EntryKind::Dir {
                if let Ok(sub) = dir_path.join_segment(&name)
                    && let Ok(main_rs) = sub.join_segment("main.rs")
                    && tree_exists_following_symlinks(self.tree, &main_rs)
                {
                    out.push((name.clone(), format!("{subdir}/{name}/main.rs")));
                }
            } else if let Some(stem) = name.strip_suffix(".rs")
                && !stem.is_empty()
            {
                out.push((stem.to_owned(), format!("{subdir}/{name}")));
            }
        }
        Ok(out)
    }

    fn extract_targets(
        &self,
        raw: &toml::Table,
        pkg: &toml::Table,
        package_root: Option<&RepoRelPath>,
        package_name: &str,
        edition: &str,
        manifest_path: &RepoRelPath,
    ) -> Result<Vec<StaticCargoTarget>, CargoStaticError> {
        let origin = manifest_path.as_str();
        if pkg.contains_key("metabuild")
            || pkg.contains_key("default-target")
            || pkg.contains_key("forced-target")
        {
            return Err(CargoStaticError::Manifest {
                path: origin.to_owned(),
                reason:
                    "unstable nightly `metabuild`/`default-target`/`forced-target` is unsupported"
                        .to_owned(),
            });
        }

        let mut targets = Vec::new();

        let are_normalized =
            |toml_targets: Option<&Vec<toml::Value>>, autodiscover: Option<bool>| -> bool {
                if autodiscover != Some(false) {
                    return false;
                }
                let Some(arr) = toml_targets else {
                    return true;
                };
                arr.iter().all(|v| {
                    v.as_table()
                        .is_some_and(|t| t.contains_key("name") && t.contains_key("path"))
                })
            };

        // 1. `[lib]`
        let orig_lib = raw.get("lib").and_then(toml::Value::as_table);
        let autolib = pkg.get("autolib").and_then(toml::Value::as_bool);
        let lib_as_vec = orig_lib.map(|t| vec![toml::Value::Table(t.clone())]);
        let mut lib_resolved: Option<(String, String, Vec<String>)> = None;

        let src_lib_exists = resolve_repo_rel(package_root, "src/lib.rs", origin)?
            .is_some_and(|p| tree_exists_following_symlinks(self.tree, &p));

        let extract_lib_kinds =
            |ltbl: Option<&toml::Table>, ed: &str| -> Result<Vec<String>, CargoStaticError> {
                let Some(t) = ltbl else {
                    return Ok(vec!["lib".to_owned()]);
                };
                if ed == "2024" && (t.contains_key("proc_macro") || t.contains_key("crate_type")) {
                    return Err(CargoStaticError::Manifest {
                        path: origin.to_owned(),
                        reason: "deprecated `proc_macro`/`crate_type` rejected in Edition 2024"
                            .to_owned(),
                    });
                }
                let crate_types: Option<Vec<String>> = t
                    .get("crate-type")
                    .or_else(|| t.get("crate_type"))
                    .and_then(toml::Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(toml::Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    });
                let proc_macro = t
                    .get("proc-macro")
                    .or_else(|| t.get("proc_macro"))
                    .and_then(toml::Value::as_bool);
                if let Some(ct) = crate_types
                    && !ct.is_empty()
                {
                    let mut sorted = ct;
                    sorted.sort();
                    return Ok(sorted);
                }
                if proc_macro == Some(true) {
                    Ok(vec!["proc-macro".to_owned()])
                } else {
                    Ok(vec!["lib".to_owned()])
                }
            };

        if are_normalized(lib_as_vec.as_ref(), autolib) {
            if let Some(ltbl) = orig_lib {
                let lname = ltbl
                    .get("name")
                    .and_then(toml::Value::as_str)
                    .unwrap_or(&package_name.replace('-', "_"))
                    .to_owned();
                let lpath = ltbl
                    .get("path")
                    .and_then(toml::Value::as_str)
                    .ok_or_else(|| CargoStaticError::Manifest {
                        path: origin.to_owned(),
                        reason: "missing lib.path".to_owned(),
                    })?
                    .to_owned();
                lib_resolved = Some((lname, lpath, extract_lib_kinds(Some(ltbl), edition)?));
            }
        } else if orig_lib.is_some() || src_lib_exists {
            let lname = orig_lib
                .and_then(|t| t.get("name"))
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| package_name.replace('-', "_"));
            let explicit_path = orig_lib
                .and_then(|t| t.get("path"))
                .and_then(toml::Value::as_str)
                .map(str::to_owned);
            let lpath = if let Some(ep) = explicit_path {
                ep
            } else if src_lib_exists {
                "src/lib.rs".to_owned()
            } else if edition == "2015" {
                let leg_rel = format!("src/{lname}.rs");
                let leg_exists = resolve_repo_rel(package_root, &leg_rel, origin)?
                    .is_some_and(|p| tree_exists_following_symlinks(self.tree, &p));
                if leg_exists {
                    leg_rel
                } else {
                    return Err(CargoStaticError::Manifest {
                        path: origin.to_owned(),
                        reason: format!("cannot find `[lib]` target `{lname}`"),
                    });
                }
            } else {
                return Err(CargoStaticError::Manifest {
                    path: origin.to_owned(),
                    reason: format!("cannot find `[lib]` target `{lname}`"),
                });
            };
            lib_resolved = Some((lname, lpath, extract_lib_kinds(orig_lib, edition)?));
        }

        let has_lib = lib_resolved.is_some();
        if let Some((lname, lpath, lkinds)) = lib_resolved {
            let src_path = resolve_repo_rel(package_root, &lpath, origin)?.ok_or_else(|| {
                CargoStaticError::Manifest {
                    path: origin.to_owned(),
                    reason: format!("invalid lib target path `{lpath}`"),
                }
            })?;
            targets.push(StaticCargoTarget {
                kinds: lkinds,
                name: lname,
                src_path,
            });
        }

        // Helper for `[[bin]]`, `[[example]]`, `[[test]]`, `[[bench]]`
        let resolve_multi_targets = |toml_key: &str,
                                     auto_key: &str,
                                     kind_str: &str,
                                     inferred: Vec<(String, String)>,
                                     legacy_fn: &dyn Fn(
            &str,
        ) -> Result<
            Option<String>,
            CargoStaticError,
        >|
         -> Result<Vec<StaticCargoTarget>, CargoStaticError> {
            let orig_arr = raw.get(toml_key).and_then(toml::Value::as_array);
            let auto_flag = pkg.get(auto_key).and_then(toml::Value::as_bool);
            let mut entries: Vec<(String, Option<String>)> = Vec::new();

            if are_normalized(orig_arr, auto_flag) {
                if let Some(arr) = orig_arr {
                    for item in arr {
                        let t = item.as_table().ok_or_else(|| CargoStaticError::Manifest {
                            path: origin.to_owned(),
                            reason: format!("`[[{toml_key}]]` must be a table"),
                        })?;
                        let n = t.get("name").and_then(toml::Value::as_str).ok_or_else(|| {
                            CargoStaticError::Manifest {
                                path: origin.to_owned(),
                                reason: format!("`[[{toml_key}]]` missing `name`"),
                            }
                        })?;
                        let p = t.get("path").and_then(toml::Value::as_str);
                        entries.push((n.to_owned(), p.map(str::to_owned)));
                    }
                }
            } else {
                let inf_resolved: Vec<(String, String, Option<RepoRelPath>)> = inferred
                    .iter()
                    .map(|(n, p)| {
                        Ok((
                            n.clone(),
                            p.clone(),
                            resolve_repo_rel(package_root, p, origin)?,
                        ))
                    })
                    .collect::<Result<_, CargoStaticError>>()?;

                if let Some(arr) = orig_arr {
                    let mut seen_names = BTreeSet::new();
                    let mut seen_paths = BTreeSet::new();
                    for item in arr {
                        let t = item.as_table().ok_or_else(|| CargoStaticError::Manifest {
                            path: origin.to_owned(),
                            reason: format!("`[[{toml_key}]]` must be a table"),
                        })?;
                        let n = t.get("name").and_then(toml::Value::as_str).ok_or_else(|| {
                            CargoStaticError::Manifest {
                                path: origin.to_owned(),
                                reason: format!("`[[{toml_key}]]` missing `name`"),
                            }
                        })?;
                        let p = t.get("path").and_then(toml::Value::as_str);
                        seen_names.insert(n.to_owned());
                        if let Some(ps) = p {
                            seen_paths.insert(resolve_repo_rel(package_root, ps, origin)?);
                        }
                        entries.push((n.to_owned(), p.map(str::to_owned)));
                    }
                    let auto_eff = auto_flag.unwrap_or(edition != "2015");
                    if auto_eff {
                        for (inf_n, inf_p, inf_abs) in &inf_resolved {
                            if !seen_names.contains(inf_n) && !seen_paths.contains(inf_abs) {
                                entries.push((inf_n.clone(), Some(inf_p.clone())));
                            }
                        }
                    }
                } else if auto_flag != Some(false) {
                    for (inf_n, inf_p, _) in &inf_resolved {
                        entries.push((inf_n.clone(), Some(inf_p.clone())));
                    }
                }
                entries.sort_by(|a, b| a.0.cmp(&b.0));

                for (name, path_opt) in &mut entries {
                    if path_opt.is_none() {
                        let matches: Vec<&str> = inferred
                            .iter()
                            .filter(|(n, _)| n == name)
                            .map(|(_, p)| p.as_str())
                            .collect();
                        if matches.len() == 1 {
                            *path_opt = Some(matches[0].to_owned());
                        } else if edition == "2015" {
                            if let Some(lp) = legacy_fn(name)? {
                                *path_opt = Some(lp);
                            } else if kind_str == "bin" {
                                return Err(CargoStaticError::Manifest {
                                    path: origin.to_owned(),
                                    reason: format!("cannot resolve {kind_str} target `{name}`"),
                                });
                            }
                        } else if kind_str == "bin" {
                            return Err(CargoStaticError::Manifest {
                                path: origin.to_owned(),
                                reason: format!("cannot resolve {kind_str} target `{name}`"),
                            });
                        }
                    }
                }
            }

            let mut resolved_targets = Vec::new();
            for (name, path_opt) in entries {
                // In Cargo (`targets.rs`), unresolved/ambiguous pathless `[[bin]]`
                // targets hard-error above, whereas unresolved/ambiguous pathless
                // `[[example]]`, `[[test]]`, and `[[bench]]` targets emit a deferred
                // warning and are omitted from normalized `targets`.
                let Some(rel_p) = path_opt else {
                    continue;
                };
                let src_path =
                    resolve_repo_rel(package_root, &rel_p, origin)?.ok_or_else(|| {
                        CargoStaticError::Manifest {
                            path: origin.to_owned(),
                            reason: format!("invalid {kind_str} target path `{rel_p}`"),
                        }
                    })?;
                resolved_targets.push(StaticCargoTarget {
                    kinds: vec![kind_str.to_owned()],
                    name,
                    src_path,
                });
            }
            Ok(resolved_targets)
        };

        // 2. `[[bin]]`
        let mut inf_bins = Vec::new();
        if resolve_repo_rel(package_root, "src/main.rs", origin)?
            .is_some_and(|p| tree_exists_following_symlinks(self.tree, &p))
        {
            inf_bins.push((package_name.to_owned(), "src/main.rs".to_owned()));
        }
        inf_bins.extend(self.infer_from_directory(package_root, "src/bin", origin)?);
        targets.extend(resolve_multi_targets(
            "bin",
            "autobins",
            "bin",
            inf_bins,
            &|name| {
                if !has_lib {
                    let cand = format!("src/{name}.rs");
                    if resolve_repo_rel(package_root, &cand, origin)?
                        .is_some_and(|p| tree_exists_following_symlinks(self.tree, &p))
                    {
                        return Ok(Some(cand));
                    }
                }
                for cand in ["src/main.rs", "src/bin/main.rs"] {
                    if resolve_repo_rel(package_root, cand, origin)?
                        .is_some_and(|p| tree_exists_following_symlinks(self.tree, &p))
                    {
                        return Ok(Some(cand.to_owned()));
                    }
                }
                Ok(None)
            },
        )?);

        // 3. `[[example]]`, `[[test]]`, `[[bench]]`
        for (toml_key, dir_name, auto_key, kind_str) in [
            ("example", "examples", "autoexamples", "example"),
            ("test", "tests", "autotests", "test"),
            ("bench", "benches", "autobenches", "bench"),
        ] {
            let inf = self.infer_from_directory(package_root, dir_name, origin)?;
            targets.extend(resolve_multi_targets(
                toml_key,
                auto_key,
                kind_str,
                inf,
                &|name| {
                    if kind_str == "bench"
                        && name == "bench"
                        && resolve_repo_rel(package_root, "src/bench.rs", origin)?
                            .is_some_and(|p| tree_follows_to_file(self.tree, &p))
                    {
                        return Ok(Some("src/bench.rs".to_owned()));
                    }
                    Ok(None)
                },
            )?);
        }

        // 4. `package.build` (`custom-build`)
        let build_script: Option<String> = match pkg.get("build") {
            None => {
                if resolve_repo_rel(package_root, "build.rs", origin)?
                    .is_some_and(|p| tree_follows_to_file(self.tree, &p))
                {
                    Some("build.rs".to_owned())
                } else {
                    None
                }
            }
            Some(toml::Value::Boolean(false)) => None,
            Some(toml::Value::Boolean(true)) => Some("build.rs".to_owned()),
            Some(toml::Value::String(s)) => Some(s.clone()),
            Some(toml::Value::Array(_)) => {
                return Err(CargoStaticError::Manifest {
                    path: origin.to_owned(),
                    reason: "unstable nightly `package.build = [...]` is unsupported".to_owned(),
                });
            }
            Some(_) => {
                return Err(CargoStaticError::Manifest {
                    path: origin.to_owned(),
                    reason: "invalid `package.build` value".to_owned(),
                });
            }
        };

        if let Some(script_rel) = build_script {
            let src_path =
                resolve_repo_rel(package_root, &script_rel, origin)?.ok_or_else(|| {
                    CargoStaticError::Manifest {
                        path: origin.to_owned(),
                        reason: format!("invalid build script path `{script_rel}`"),
                    }
                })?;
            let fname = src_path.file_name();
            let stem = fname.strip_suffix(".rs").unwrap_or(fname);
            targets.push(StaticCargoTarget {
                kinds: vec!["custom-build".to_owned()],
                name: format!("build-script-{stem}"),
                src_path,
            });
        }

        Ok(targets)
    }

    fn normalize_readme_val(
        &self,
        root_dir: Option<&RepoRelPath>,
        val: Option<&toml::Value>,
        origin: &str,
    ) -> Result<Option<String>, CargoStaticError> {
        match val {
            None => {
                for fname in DEFAULT_README_FILES {
                    if let Some(cand) = resolve_repo_rel(root_dir, fname, origin)?
                        && tree_follows_to_file(self.tree, &cand)
                    {
                        return Ok(Some(fname.to_owned()));
                    }
                }
                Ok(None)
            }
            Some(toml::Value::Boolean(false)) => Ok(None),
            Some(toml::Value::Boolean(true)) => Ok(Some("README.md".to_owned())),
            Some(toml::Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(CargoStaticError::Manifest {
                path: origin.to_owned(),
                reason: "invalid `readme` value".to_owned(),
            }),
        }
    }

    fn parse_package(
        &mut self,
        manifest_path: &RepoRelPath,
        ws_root_manifest: Option<&RepoRelPath>,
    ) -> Result<StaticPackage, CargoStaticError> {
        let origin = manifest_path.as_str();
        let package_root = manifest_path.parent();
        let raw = self.load_raw(manifest_path)?;
        let Some((pkg, used_deprecated_project)) = Self::get_pkg_table(&raw, manifest_path)? else {
            return Err(CargoStaticError::Manifest {
                path: manifest_path.to_string(),
                reason: "expected `[package]` manifest".to_owned(),
            });
        };

        let resolved_ws_manifest = match ws_root_manifest {
            Some(m) => Some(m.clone()),
            None => self.find_workspace_root(manifest_path)?,
        };
        let ws_data: Option<(Option<RepoRelPath>, toml::Table)> = match &resolved_ws_manifest {
            Some(wm) => {
                let wraw = self.load_raw(wm)?;
                wraw.get("workspace")
                    .and_then(toml::Value::as_table)
                    .map(|wt| (wm.parent(), wt.clone()))
            }
            None => None,
        };
        let require_ws = || -> Result<&(Option<RepoRelPath>, toml::Table), CargoStaticError> {
            ws_data.as_ref().ok_or_else(|| CargoStaticError::Manifest {
                path: manifest_path.to_string(),
                reason: "failed to find workspace root for `.workspace = true` inheritance"
                    .to_owned(),
            })
        };

        let name = pkg
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| CargoStaticError::Manifest {
                path: manifest_path.to_string(),
                reason: "`[package]` missing `name`".to_owned(),
            })?
            .to_owned();

        let edition = match pkg.get("edition") {
            Some(toml::Value::Table(t))
                if t.get("workspace").and_then(toml::Value::as_bool) == Some(true) =>
            {
                let (_, wtbl) = require_ws()?;
                wtbl.get("package")
                    .and_then(toml::Value::as_table)
                    .and_then(|wp| wp.get("edition"))
                    .and_then(toml::Value::as_str)
                    .unwrap_or("2015")
                    .to_owned()
            }
            Some(toml::Value::String(s)) => s.clone(),
            None => "2015".to_owned(),
            Some(_) => {
                return Err(CargoStaticError::Manifest {
                    path: manifest_path.to_string(),
                    reason: "invalid `package.edition`".to_owned(),
                });
            }
        };

        if edition == "2024" && used_deprecated_project {
            return Err(CargoStaticError::Manifest {
                path: manifest_path.to_string(),
                reason: "`[project]` is rejected in Edition 2024".to_owned(),
            });
        }
        if edition == "2024"
            && (raw.contains_key("dev_dependencies") || raw.contains_key("build_dependencies"))
        {
            return Err(CargoStaticError::Manifest {
                path: manifest_path.to_string(),
                reason: "underscore `*_dependencies` tables are rejected in Edition 2024"
                    .to_owned(),
            });
        }

        let readme = match pkg.get("readme") {
            Some(toml::Value::Table(t))
                if t.get("workspace").and_then(toml::Value::as_bool) == Some(true) =>
            {
                let (ws_dir, wtbl) = require_ws()?;
                let ws_rd_val = wtbl
                    .get("package")
                    .and_then(toml::Value::as_table)
                    .and_then(|wp| wp.get("readme"));
                let ws_rd = self
                    .normalize_readme_val(ws_dir.as_ref(), ws_rd_val, origin)?
                    .ok_or_else(|| CargoStaticError::Manifest {
                        path: manifest_path.to_string(),
                        reason: "`workspace.package.readme` was not defined".to_owned(),
                    })?;
                let target_p = resolve_repo_rel(ws_dir.as_ref(), &ws_rd, origin)?;
                Some(diff_repo_dirs(package_root.as_ref(), target_p.as_ref()))
            }
            other => self.normalize_readme_val(package_root.as_ref(), other, origin)?,
        };
        let readme_repo_path = match &readme {
            Some(r) => resolve_repo_rel(package_root.as_ref(), r, origin)?,
            None => None,
        };

        let license_file = match pkg.get("license-file") {
            Some(toml::Value::Table(t))
                if t.get("workspace").and_then(toml::Value::as_bool) == Some(true) =>
            {
                let (ws_dir, wtbl) = require_ws()?;
                let ws_lf = wtbl
                    .get("package")
                    .and_then(toml::Value::as_table)
                    .and_then(|wp| wp.get("license-file"))
                    .and_then(toml::Value::as_str)
                    .ok_or_else(|| CargoStaticError::Manifest {
                        path: manifest_path.to_string(),
                        reason: "`workspace.package.license-file` was not defined".to_owned(),
                    })?;
                let target_p = resolve_repo_rel(ws_dir.as_ref(), ws_lf, origin)?;
                Some(diff_repo_dirs(package_root.as_ref(), target_p.as_ref()))
            }
            Some(toml::Value::String(s)) => Some(s.clone()),
            None => None,
            Some(_) => {
                return Err(CargoStaticError::Manifest {
                    path: manifest_path.to_string(),
                    reason: "invalid `package.license-file`".to_owned(),
                });
            }
        };
        let license_file_repo_path = match &license_file {
            Some(lf) => resolve_repo_rel(package_root.as_ref(), lf, origin)?,
            None => None,
        };

        let targets = self.extract_targets(
            &raw,
            &pkg,
            package_root.as_ref(),
            &name,
            &edition,
            manifest_path,
        )?;

        let mut path_deps = Vec::new();
        let mut collect_dep_table = |tbl: Option<&toml::Table>,
                                     dep_kind: Option<&str>,
                                     target_cfg: Option<&str>|
         -> Result<(), CargoStaticError> {
            let Some(tbl) = tbl else {
                return Ok(());
            };
            for (toml_key, spec_val) in tbl {
                let Some(spec) = spec_val.as_table() else {
                    continue;
                };
                let (resolved_spec, mut base_dir) =
                    if spec.get("workspace").and_then(toml::Value::as_bool) == Some(true) {
                        let (ws_dir, wtbl) = require_ws()?;
                        let ws_dep = wtbl
                            .get("dependencies")
                            .and_then(toml::Value::as_table)
                            .and_then(|d| d.get(toml_key))
                            .ok_or_else(|| CargoStaticError::Manifest {
                                path: manifest_path.to_string(),
                                reason: format!("workspace dependency `{toml_key}` not found"),
                            })?;
                        let Some(ws_spec) = ws_dep.as_table() else {
                            continue;
                        };
                        (ws_spec, ws_dir.clone())
                    } else {
                        (spec, package_root.clone())
                    };

                if let Some(base_val) = resolved_spec.get("base") {
                    let Some(base_name) = base_val.as_str() else {
                        return Err(CargoStaticError::Manifest {
                            path: manifest_path.to_string(),
                            reason: "invalid dependency `base`".to_owned(),
                        });
                    };
                    if base_name == "workspace" {
                        let (ws_dir, _) = require_ws()?;
                        base_dir = ws_dir.clone();
                    } else {
                        return Err(CargoStaticError::Manifest {
                            path: manifest_path.to_string(),
                            reason: format!(
                                "unstable `-Zpath-bases` custom base `{base_name}` is unsupported"
                            ),
                        });
                    }
                }

                if let Some(rel_p) = resolved_spec.get("path").and_then(toml::Value::as_str) {
                    let resolved_dir = resolve_repo_rel(base_dir.as_ref(), rel_p, origin)?;
                    let (dep_name, rename) =
                        match resolved_spec.get("package").and_then(toml::Value::as_str) {
                            Some(actual) => (actual.to_owned(), Some(toml_key.clone())),
                            None => (toml_key.clone(), None),
                        };
                    path_deps.push(StaticPathDep {
                        name: dep_name,
                        rename,
                        kind: dep_kind.map(str::to_owned),
                        target: target_cfg.map(str::to_owned),
                        path: resolved_dir,
                    });
                }
            }
            Ok(())
        };

        collect_dep_table(
            raw.get("dependencies").and_then(toml::Value::as_table),
            None,
            None,
        )?;
        collect_dep_table(
            raw.get("dev-dependencies")
                .or_else(|| raw.get("dev_dependencies"))
                .and_then(toml::Value::as_table),
            Some("dev"),
            None,
        )?;
        collect_dep_table(
            raw.get("build-dependencies")
                .or_else(|| raw.get("build_dependencies"))
                .and_then(toml::Value::as_table),
            Some("build"),
            None,
        )?;
        if let Some(targets_tbl) = raw.get("target").and_then(toml::Value::as_table) {
            for (cfg_key, plat_val) in targets_tbl {
                if let Some(plat) = plat_val.as_table() {
                    if edition == "2024"
                        && (plat.contains_key("dev_dependencies")
                            || plat.contains_key("build_dependencies"))
                    {
                        return Err(CargoStaticError::Manifest {
                            path: manifest_path.to_string(),
                            reason: "underscore `*_dependencies` tables rejected in Edition 2024"
                                .to_owned(),
                        });
                    }
                    collect_dep_table(
                        plat.get("dependencies").and_then(toml::Value::as_table),
                        None,
                        Some(cfg_key),
                    )?;
                    collect_dep_table(
                        plat.get("build-dependencies")
                            .or_else(|| plat.get("build_dependencies"))
                            .and_then(toml::Value::as_table),
                        Some("build"),
                        Some(cfg_key),
                    )?;
                    collect_dep_table(
                        plat.get("dev-dependencies")
                            .or_else(|| plat.get("dev_dependencies"))
                            .and_then(toml::Value::as_table),
                        Some("dev"),
                        Some(cfg_key),
                    )?;
                }
            }
        }

        Ok(StaticPackage {
            name,
            edition,
            manifest_path: manifest_path.clone(),
            package_root,
            readme,
            license_file,
            readme_repo_path,
            license_file_repo_path,
            targets,
            path_deps,
            has_workspace_table: raw.contains_key("workspace"),
        })
    }
}

/// Discovers the complete Cargo workspace, members, targets, external path
/// dependencies, `[patch]`/`[replace]` paths, `Cargo.lock`, `.cargo/config`
/// hierarchy, and `rust-toolchain` files for `manifest_path` (`0` `cargo`
/// subprocesses).
pub fn discover_workspace(
    tree: &dyn SourceTree,
    manifest_path: &RepoRelPath,
    extra_walk_workdirs: &[Option<RepoRelPath>],
) -> Result<StaticWorkspaceDiscovery, CargoStaticError> {
    let mut analyzer = Analyzer::new(tree);
    let root_manifest_opt = analyzer.find_workspace_root(manifest_path)?;
    let root_manifest = root_manifest_opt
        .clone()
        .unwrap_or_else(|| manifest_path.clone());
    let ws_root_dir = root_manifest.parent();
    let origin = root_manifest.as_str();

    let raw_root = analyzer.load_raw(&root_manifest)?;
    let ws_table = raw_root
        .get("workspace")
        .and_then(toml::Value::as_table)
        .cloned();
    let is_virtual = Analyzer::get_pkg_table(&raw_root, &root_manifest)?.is_none();

    let mut members: BTreeMap<RepoRelPath, StaticPackage> = BTreeMap::new();
    let mut member_order: Vec<RepoRelPath> = Vec::new();
    let mut seen_members: BTreeSet<RepoRelPath> = BTreeSet::new();
    let mut ws_roots_in_members: Vec<Option<RepoRelPath>> = Vec::new();

    #[allow(clippy::too_many_arguments)]
    fn find_path_deps_rec(
        analyzer: &mut Analyzer<'_>,
        mp: RepoRelPath,
        is_path_dep: bool,
        ws_root_dir: Option<&RepoRelPath>,
        root_manifest_opt: Option<&RepoRelPath>,
        ws_table: Option<&toml::Table>,
        origin: &str,
        seen_members: &mut BTreeSet<RepoRelPath>,
        member_order: &mut Vec<RepoRelPath>,
        ws_roots_in_members: &mut Vec<Option<RepoRelPath>>,
        members: &mut BTreeMap<RepoRelPath, StaticPackage>,
    ) -> Result<(), CargoStaticError> {
        if seen_members.contains(&mp) {
            return Ok(());
        }
        if is_path_dep
            && !dir_starts_with(mp.parent().as_ref(), ws_root_dir)
            && analyzer.find_workspace_root(&mp)?.as_ref() != root_manifest_opt
        {
            return Ok(());
        }
        if let Some(wt) = ws_table
            && Analyzer::is_excluded(ws_root_dir, wt, &mp, origin)?
        {
            return Ok(());
        }
        seen_members.insert(mp.clone());
        member_order.push(mp.clone());
        let raw_m = analyzer.load_raw(&mp)?;
        if raw_m.contains_key("workspace") {
            ws_roots_in_members.push(mp.parent());
        }
        if Analyzer::get_pkg_table(&raw_m, &mp)?.is_none() {
            return Ok(());
        }
        let sp = analyzer.parse_package(&mp, root_manifest_opt)?;
        let child_deps: Vec<RepoRelPath> = sp
            .path_deps
            .iter()
            .map(|d| manifest_in_dir(d.path.as_ref()))
            .collect();
        members.insert(mp, sp);
        for child_mp in child_deps {
            find_path_deps_rec(
                analyzer,
                child_mp,
                true,
                ws_root_dir,
                root_manifest_opt,
                ws_table,
                origin,
                seen_members,
                member_order,
                ws_roots_in_members,
                members,
            )?;
        }
        Ok(())
    }

    let default_members: Vec<RepoRelPath>;
    if root_manifest_opt.is_none() {
        let sp = analyzer.parse_package(manifest_path, None)?;
        members.insert(manifest_path.clone(), sp);
        member_order.push(manifest_path.clone());
        default_members = vec![manifest_path.clone()];
    } else {
        let wt = ws_table
            .as_ref()
            .ok_or_else(|| CargoStaticError::Manifest {
                path: root_manifest.to_string(),
                reason: "workspace root missing `[workspace]` table".to_owned(),
            })?;
        let raw_globs: Vec<String> = wt
            .get("members")
            .and_then(toml::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(toml::Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let members_paths =
            analyzer.expand_members_paths(ws_root_dir.as_ref(), &raw_globs, origin)?;
        for (p_dir, _) in &members_paths {
            find_path_deps_rec(
                &mut analyzer,
                manifest_in_dir(p_dir.as_ref()),
                false,
                ws_root_dir.as_ref(),
                root_manifest_opt.as_ref(),
                Some(wt),
                origin,
                &mut seen_members,
                &mut member_order,
                &mut ws_roots_in_members,
                &mut members,
            )?;
        }
        find_path_deps_rec(
            &mut analyzer,
            root_manifest.clone(),
            false,
            ws_root_dir.as_ref(),
            root_manifest_opt.as_ref(),
            Some(wt),
            origin,
            &mut seen_members,
            &mut member_order,
            &mut ws_roots_in_members,
            &mut members,
        )?;

        if ws_roots_in_members.len() > 1 {
            return Err(CargoStaticError::Manifest {
                path: root_manifest.to_string(),
                reason: "multiple workspace roots found in the same workspace".to_owned(),
            });
        }

        if &root_manifest == manifest_path && wt.contains_key("default-members") {
            let def_globs: Vec<String> = wt
                .get("default-members")
                .and_then(toml::Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(toml::Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let def_paths =
                analyzer.expand_members_paths(ws_root_dir.as_ref(), &def_globs, origin)?;
            let mut defs = Vec::new();
            for (d_dir, _) in def_paths {
                let dm = manifest_in_dir(d_dir.as_ref());
                if !members.contains_key(&dm) {
                    let in_orig = members_paths.iter().any(|(m, _)| m == &d_dir);
                    if in_orig && Analyzer::is_excluded(ws_root_dir.as_ref(), wt, &dm, origin)? {
                        continue;
                    }
                    return Err(CargoStaticError::Manifest {
                        path: root_manifest.to_string(),
                        reason: format!("`default-members` entry `{dm}` is not a workspace member"),
                    });
                }
                defs.push(dm);
            }
            default_members = defs;
        } else if is_virtual {
            default_members = member_order
                .iter()
                .filter(|mp| members.contains_key(*mp))
                .cloned()
                .collect();
        } else {
            default_members = vec![manifest_path.clone()];
        }
    }

    let mut patch_paths: BTreeSet<Option<RepoRelPath>> = BTreeSet::new();
    if let Some(raw_patch) = raw_root.get("patch").and_then(toml::Value::as_table) {
        for pmap in raw_patch.values() {
            if let Some(ptbl) = pmap.as_table() {
                for spec in ptbl.values() {
                    if let Some(stbl) = spec.as_table()
                        && let Some(ps) = stbl.get("path").and_then(toml::Value::as_str)
                    {
                        patch_paths.insert(resolve_repo_rel(ws_root_dir.as_ref(), ps, origin)?);
                    }
                }
            }
        }
    }

    let mut replace_paths: BTreeSet<Option<RepoRelPath>> = BTreeSet::new();
    if let Some(raw_rep) = raw_root.get("replace").and_then(toml::Value::as_table) {
        if raw_root.contains_key("patch") {
            return Err(CargoStaticError::Manifest {
                path: root_manifest.to_string(),
                reason: "cannot specify both `[patch]` and `[replace]`".to_owned(),
            });
        }
        for spec in raw_rep.values() {
            if let Some(stbl) = spec.as_table()
                && let Some(ps) = stbl.get("path").and_then(toml::Value::as_str)
            {
                replace_paths.insert(resolve_repo_rel(ws_root_dir.as_ref(), ps, origin)?);
            }
        }
    }

    // Discover configs from `ws_root_dir` first (authoritative for lockfile
    // override), then union upward walks from every discovered crate dir and
    // `extra_walk_workdirs` (`CargoStandardPaths` rule).
    let primary_configs = discover_cargo_configs_from_dir(tree, ws_root_dir.as_ref())?;
    for cfg in &primary_configs {
        for pp in &cfg.patch_paths {
            patch_paths.insert(pp.clone());
        }
    }

    let mut lockfile_path = match &ws_root_dir {
        None => RepoRelPath::new("Cargo.lock").expect("static"),
        Some(d) => d.join_segment("Cargo.lock").expect("static"),
    };
    for cfg in &primary_configs {
        if let Some(ref lp) = cfg.lockfile_path {
            lockfile_path = lp.clone();
            break;
        }
    }

    // Transitive crawl of external path dependencies + `[patch]` + `[replace]`.
    let mut external_path_deps: BTreeMap<RepoRelPath, StaticPackage> = BTreeMap::new();
    let mut queue: Vec<RepoRelPath> = Vec::new();
    for sp in members.values() {
        for pdep in &sp.path_deps {
            queue.push(manifest_in_dir(pdep.path.as_ref()));
        }
    }
    for pp in patch_paths.iter().chain(replace_paths.iter()) {
        queue.push(manifest_in_dir(pp.as_ref()));
    }
    while let Some(mp) = queue.pop() {
        if members.contains_key(&mp) || external_path_deps.contains_key(&mp) {
            continue;
        }
        let ext_pkg = analyzer.parse_package(&mp, None)?;
        for pdep in &ext_pkg.path_deps {
            queue.push(manifest_in_dir(pdep.path.as_ref()));
        }
        external_path_deps.insert(mp, ext_pkg);
    }

    // Walk `.cargo/config(.toml)` and `rust-toolchain(.toml)` upward from
    // `cargo_crate_dirs ∪ extra_walk_workdirs`.
    let mut walk_starts: BTreeSet<Option<RepoRelPath>> = BTreeSet::new();
    walk_starts.insert(ws_root_dir.clone());
    for pkg in members.values().chain(external_path_deps.values()) {
        walk_starts.insert(pkg.package_root.clone());
    }
    for d in extra_walk_workdirs {
        walk_starts.insert(d.clone());
    }

    let mut all_configs = primary_configs;
    let mut seen_cfg_paths: BTreeSet<RepoRelPath> =
        all_configs.iter().map(|c| c.path.clone()).collect();
    let mut rust_toolchain_files: BTreeSet<RepoRelPath> = BTreeSet::new();

    for start in &walk_starts {
        for cfg in discover_cargo_configs_from_dir(tree, start.as_ref())? {
            if seen_cfg_paths.insert(cfg.path.clone()) {
                for pp in &cfg.patch_paths {
                    if patch_paths.insert(pp.clone()) {
                        let pmp = manifest_in_dir(pp.as_ref());
                        if !members.contains_key(&pmp) && !external_path_deps.contains_key(&pmp) {
                            let ext_pkg = analyzer.parse_package(&pmp, None)?;
                            external_path_deps.insert(pmp, ext_pkg);
                        }
                    }
                }
                all_configs.push(cfg);
            }
        }
        for rt in discover_rust_toolchains_from_dir(tree, start.as_ref())? {
            rust_toolchain_files.insert(rt);
        }
    }

    let lockfile_exists = tree_follows_to_file(tree, &lockfile_path);

    Ok(StaticWorkspaceDiscovery {
        workspace_root: ws_root_dir,
        root_manifest,
        is_virtual,
        members,
        default_members,
        external_path_deps,
        patch_path_deps: patch_paths.into_iter().collect(),
        replace_path_deps: replace_paths.into_iter().collect(),
        lockfile_path,
        lockfile_exists,
        config_files: all_configs,
        rust_toolchain_files,
    })
}

/// Expands the `CargoStandardPaths` CI source closure for a discovered
/// workspace (`0` pruning by `package.include` or `package.exclude`).
pub fn expand_cargo_standard_paths(
    tree: &dyn SourceTree,
    discovery: &StaticWorkspaceDiscovery,
    all_tree_paths: &[RepoRelPath],
    exclude_globs: &[String],
) -> Result<BTreeSet<RepoRelPath>, CargoStaticError> {
    let exc_set = crate::tree::compile_selector_globset(exclude_globs)?;

    let mut exact_paths: BTreeSet<RepoRelPath> = BTreeSet::new();
    let mut subtree_prefixes: BTreeSet<Option<RepoRelPath>> = BTreeSet::new();

    exact_paths.insert(discovery.root_manifest.clone());
    if discovery.lockfile_exists && tree.kind_of(&discovery.lockfile_path)?.is_some() {
        exact_paths.insert(discovery.lockfile_path.clone());
    }
    for cfg in &discovery.config_files {
        if cfg.exists {
            exact_paths.insert(cfg.path.clone());
        }
        for vd in &cfg.vendored_dirs {
            subtree_prefixes.insert(vd.clone());
        }
        for lr in &cfg.local_registries {
            subtree_prefixes.insert(lr.clone());
        }
    }
    for rt in &discovery.rust_toolchain_files {
        if tree.kind_of(rt)?.is_some() {
            exact_paths.insert(rt.clone());
        }
    }

    for pkg in discovery
        .members
        .values()
        .chain(discovery.external_path_deps.values())
    {
        exact_paths.insert(pkg.manifest_path.clone());
        for std_sub in ["src", "tests", "benches", "examples"] {
            let sub = match &pkg.package_root {
                None => RepoRelPath::new(std_sub).expect("static"),
                Some(r) => r.join_segment(std_sub).expect("static"),
            };
            subtree_prefixes.insert(Some(sub));
        }
        for target in &pkg.targets {
            if tree.kind_of(&target.src_path)?.is_some() {
                exact_paths.insert(target.src_path.clone());
            }
        }
        if let Some(ref rd) = pkg.readme_repo_path
            && tree.kind_of(rd)?.is_some()
        {
            exact_paths.insert(rd.clone());
        }
        if let Some(ref lf) = pkg.license_file_repo_path
            && tree.kind_of(lf)?.is_some()
        {
            exact_paths.insert(lf.clone());
        }
    }

    let has_root_subtree = subtree_prefixes.contains(&None);
    let named_prefixes: Vec<RepoRelPath> = subtree_prefixes.into_iter().flatten().collect();

    let mut closure = BTreeSet::new();
    for p in all_tree_paths {
        let matched = exact_paths.contains(p)
            || has_root_subtree
            || named_prefixes.iter().any(|pre| pre.is_prefix_of(p));
        if matched && !exc_set.is_match(p.as_str()) {
            closure.insert(p.clone());
        }
    }
    Ok(closure)
}

/// Performs the uniform dual static `cargo_locked` audit over `Cargo.lock` and
/// every discovered `Cargo.toml`, returning the minimal manifest + 0-byte
/// target stub tree for containerized pre-sandbox `cargo fetch --locked`.
pub fn audit_cargo_locked(
    tree: &dyn SourceTree,
    workspace_manifest: &RepoRelPath,
    allowed_registries: &BTreeMap<String, RegistryIndexUrl>,
) -> Result<CargoLockedFetchPlan, CargoStaticError> {
    let discovery = discover_workspace(tree, workspace_manifest, &[])?;
    let lock_path = &discovery.lockfile_path;
    if !matches!(tree.entry(lock_path)?, Some(TreeEntry::Regular { .. })) {
        return Err(CargoStaticError::LockedAudit {
            path: lock_path.to_string(),
            reason: "Cargo.lock must exist as a regular non-symlink file".to_owned(),
        });
    }
    let lock_bytes = tree.read_blob(lock_path)?;
    let lock_str = std::str::from_utf8(&lock_bytes).map_err(|e| CargoStaticError::Parse {
        path: lock_path.to_string(),
        reason: e.to_string(),
    })?;
    let lock_tbl: toml::Table = toml::from_str(lock_str).map_err(|e| CargoStaticError::Parse {
        path: lock_path.to_string(),
        reason: e.to_string(),
    })?;

    let allowed_urls: BTreeSet<&str> = allowed_registries
        .values()
        .map(RegistryIndexUrl::as_str)
        .collect();
    if let Some(pkgs) = lock_tbl.get("package").and_then(toml::Value::as_array) {
        for pkg_val in pkgs {
            if let Some(ptbl) = pkg_val.as_table()
                && let Some(src) = ptbl.get("source").and_then(toml::Value::as_str)
                && !allowed_urls.contains(src)
            {
                return Err(CargoStaticError::LockedAudit {
                    path: lock_path.to_string(),
                    reason: format!("package source {src:?} is not in allowed_registries"),
                });
            }
        }
    }

    let mut manifests = BTreeMap::new();
    let mut all_manifest_paths: BTreeSet<RepoRelPath> = BTreeSet::new();
    all_manifest_paths.insert(discovery.root_manifest.clone());
    for mp in discovery
        .members
        .keys()
        .chain(discovery.external_path_deps.keys())
    {
        all_manifest_paths.insert(mp.clone());
    }

    let root_raw = read_toml_table(tree, &discovery.root_manifest)?;
    let ws_deps_tbl = root_raw
        .get("workspace")
        .and_then(toml::Value::as_table)
        .and_then(|w| w.get("dependencies"))
        .and_then(toml::Value::as_table);

    let audit_dep_spec = |mp_str: &str,
                          dep_key: &str,
                          spec_val: &toml::Value,
                          ws_deps: Option<&toml::Table>|
     -> Result<(), CargoStaticError> {
        match spec_val {
            toml::Value::String(_) => {
                if !allowed_registries.contains_key("crates-io") {
                    return Err(CargoStaticError::LockedAudit {
                        path: mp_str.to_owned(),
                        reason: format!(
                            "dependency `{dep_key}` uses implicit `crates-io`, which is not in allowed_registries"
                        ),
                    });
                }
            }
            toml::Value::Table(t) => {
                for forbidden in ["git", "branch", "tag", "rev", "registry-index"] {
                    if t.contains_key(forbidden) {
                        return Err(CargoStaticError::LockedAudit {
                            path: mp_str.to_owned(),
                            reason: format!(
                                "dependency `{dep_key}` contains forbidden `{forbidden}` key"
                            ),
                        });
                    }
                }
                if t.get("workspace").and_then(toml::Value::as_bool) == Some(true) {
                    if let Some(wdeps) = ws_deps
                        && let Some(wspec) = wdeps.get(dep_key)
                    {
                        return match wspec {
                            toml::Value::String(_) => {
                                if !allowed_registries.contains_key("crates-io") {
                                    Err(CargoStaticError::LockedAudit {
                                        path: mp_str.to_owned(),
                                        reason: format!(
                                            "inherited workspace dependency `{dep_key}` requires `crates-io` in allowed_registries"
                                        ),
                                    })
                                } else {
                                    Ok(())
                                }
                            }
                            toml::Value::Table(wt) => {
                                for forbidden in ["git", "branch", "tag", "rev", "registry-index"] {
                                    if wt.contains_key(forbidden) {
                                        return Err(CargoStaticError::LockedAudit {
                                            path: mp_str.to_owned(),
                                            reason: format!(
                                                "workspace dependency `{dep_key}` contains forbidden `{forbidden}` key"
                                            ),
                                        });
                                    }
                                }
                                if let Some(reg) = wt.get("registry").and_then(toml::Value::as_str)
                                {
                                    if !allowed_registries.contains_key(reg) {
                                        return Err(CargoStaticError::LockedAudit {
                                            path: mp_str.to_owned(),
                                            reason: format!(
                                                "workspace dependency `{dep_key}` registry `{reg}` not in allowed_registries"
                                            ),
                                        });
                                    }
                                } else if !wt.contains_key("path")
                                    && !allowed_registries.contains_key("crates-io")
                                {
                                    return Err(CargoStaticError::LockedAudit {
                                        path: mp_str.to_owned(),
                                        reason: format!(
                                            "workspace dependency `{dep_key}` requires `crates-io` in allowed_registries"
                                        ),
                                    });
                                }
                                Ok(())
                            }
                            _ => Ok(()),
                        };
                    }
                    return Ok(());
                }
                if let Some(reg) = t.get("registry").and_then(toml::Value::as_str) {
                    if !allowed_registries.contains_key(reg) {
                        return Err(CargoStaticError::LockedAudit {
                            path: mp_str.to_owned(),
                            reason: format!(
                                "dependency `{dep_key}` registry `{reg}` is not in allowed_registries"
                            ),
                        });
                    }
                } else if !t.contains_key("path") && !allowed_registries.contains_key("crates-io") {
                    return Err(CargoStaticError::LockedAudit {
                        path: mp_str.to_owned(),
                        reason: format!(
                            "dependency `{dep_key}` omits `registry` and `crates-io` is not in allowed_registries"
                        ),
                    });
                }
            }
            _ => {}
        }
        Ok(())
    };

    for mp in &all_manifest_paths {
        if !matches!(tree.entry(mp)?, Some(TreeEntry::Regular { .. })) {
            return Err(CargoStaticError::LockedAudit {
                path: mp.to_string(),
                reason: "Cargo.toml must be a regular non-symlink file".to_owned(),
            });
        }
        let raw_bytes = tree.read_blob(mp)?;
        let raw_tbl = read_toml_table(tree, mp)?;
        let mp_s = mp.as_str();

        for top_key in [
            "dependencies",
            "dev-dependencies",
            "build-dependencies",
            "dev_dependencies",
            "build_dependencies",
        ] {
            if let Some(dtbl) = raw_tbl.get(top_key).and_then(toml::Value::as_table) {
                for (k, v) in dtbl {
                    audit_dep_spec(mp_s, k, v, ws_deps_tbl)?;
                }
            }
        }
        if let Some(wdeps) = raw_tbl
            .get("workspace")
            .and_then(toml::Value::as_table)
            .and_then(|w| w.get("dependencies"))
            .and_then(toml::Value::as_table)
        {
            // Even uninherited `[workspace.dependencies]` entries are audited
            // under the uniform dual static rule in §5.2.
            for (k, v) in wdeps {
                audit_dep_spec(mp_s, k, v, None)?;
            }
        }
        if let Some(targets_tbl) = raw_tbl.get("target").and_then(toml::Value::as_table) {
            for plat_val in targets_tbl.values() {
                if let Some(plat) = plat_val.as_table() {
                    for tk in [
                        "dependencies",
                        "dev-dependencies",
                        "build-dependencies",
                        "dev_dependencies",
                        "build_dependencies",
                    ] {
                        if let Some(dtbl) = plat.get(tk).and_then(toml::Value::as_table) {
                            for (k, v) in dtbl {
                                audit_dep_spec(mp_s, k, v, ws_deps_tbl)?;
                            }
                        }
                    }
                }
            }
        }
        if let Some(patch_tbl) = raw_tbl.get("patch").and_then(toml::Value::as_table) {
            for (patch_key, pmap_val) in patch_tbl {
                let key_allowed = allowed_registries.contains_key(patch_key)
                    || allowed_urls.contains(patch_key.as_str());
                if !key_allowed {
                    return Err(CargoStaticError::LockedAudit {
                        path: mp_s.to_owned(),
                        reason: format!("`[patch.{patch_key}]` key is not in allowed_registries"),
                    });
                }
                if let Some(pmap) = pmap_val.as_table() {
                    for (k, v) in pmap {
                        audit_dep_spec(mp_s, k, v, None)?;
                    }
                }
            }
        }
        if let Some(rep_tbl) = raw_tbl.get("replace").and_then(toml::Value::as_table) {
            for (rep_key, rep_val) in rep_tbl {
                if rep_key.contains('#')
                    || rep_key.starts_with("http")
                    || rep_key.starts_with("git+")
                {
                    let prefix_ok = allowed_urls.iter().any(|u| rep_key.starts_with(u));
                    if !prefix_ok {
                        return Err(CargoStaticError::LockedAudit {
                            path: mp_s.to_owned(),
                            reason: format!(
                                "`[replace]` key {rep_key:?} source URL is not in allowed_registries"
                            ),
                        });
                    }
                } else if !allowed_registries.contains_key("crates-io") {
                    return Err(CargoStaticError::LockedAudit {
                        path: mp_s.to_owned(),
                        reason: format!(
                            "`[replace]` key {rep_key:?} requires `crates-io` in allowed_registries"
                        ),
                    });
                }
                audit_dep_spec(mp_s, rep_key, rep_val, None)?;
            }
        }

        manifests.insert(mp.clone(), raw_bytes);
    }

    let mut target_stubs = BTreeSet::new();
    for pkg in discovery
        .members
        .values()
        .chain(discovery.external_path_deps.values())
    {
        for target in &pkg.targets {
            target_stubs.insert(target.src_path.clone());
        }
    }

    Ok(CargoLockedFetchPlan {
        workspace_manifest: discovery.root_manifest,
        lockfile: (lock_path.clone(), lock_bytes),
        manifests,
        target_stubs,
    })
}
