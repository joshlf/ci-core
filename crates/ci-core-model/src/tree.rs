//! Read-only `SourceTree` abstraction, multi-hop symlink confinement
//! validators, glob selector evaluation, and `TreeMerkle` hashing.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use globset::{Glob, GlobBuilder, GlobMatcher, GlobSet, GlobSetBuilder};
use thiserror::Error;

use crate::digest::{MerkleEntry, compute_tree_merkle};
use crate::types::{GitOid, RepoRelPath, Sha256Digest, TypeError};

/// Maximum symlink indirection depth before rejecting as a cycle or chain bomb.
const MAX_SYMLINK_HOPS: usize = 64;

/// Directory entry classification under `lstat` (non-symlink-following)
/// semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// Real directory (`040000` / `S_IFDIR`).
    Dir,
    /// Regular file (`100644` / `100755` / `S_IFREG`).
    File,
    /// Symbolic link (`120000` / `S_IFLNK`).
    Symlink,
    /// Git submodule gitlink (`160000`).
    Gitlink,
    /// Socket, FIFO, block/char device, or other irregular entry.
    Special,
}

/// Detailed non-directory entry metadata returned by `SourceTree::entry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeEntry {
    /// Regular file (`executable` reflects mode `100755` / `mode & 0o100 != 0`).
    Regular {
        /// Whether the owner executable bit is set.
        executable: bool,
    },
    /// Symbolic link with its raw target string.
    Symlink {
        /// Raw link target (not yet confinement-validated).
        target: String,
    },
    /// Submodule gitlink (`160000`), forbidden in validated closures.
    Gitlink {
        /// Referenced commit OID.
        oid: GitOid,
    },
    /// Irregular filesystem node (FIFO, socket, device), always forbidden.
    Special,
}

/// Errors produced when inspecting or validating a `SourceTree` or confined
/// directory.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TreeError {
    /// Underlying storage or Git object store read error.
    #[error("tree I/O error: {0}")]
    Io(String),
    /// Invalid path or glob pattern.
    #[error("invalid path or glob pattern: {0}")]
    InvalidPattern(String),
    /// Missing path expected to exist in the tree.
    #[error("missing tree entry `{0}`")]
    MissingPath(RepoRelPath),
    /// Forbidden gitlink (`160000`) or special node encountered.
    #[error("forbidden {kind:?} entry at `{path}`")]
    ForbiddenEntryKind {
        /// Path of the forbidden entry.
        path: RepoRelPath,
        /// Classification of the forbidden entry.
        kind: EntryKind,
    },
    /// `workdir` or one of its directory prefixes was missing or a symlink.
    #[error("workdir `{workdir}` requires real non-symlink directories (failed at `{at}`)")]
    InvalidWorkdir {
        /// Configured check working directory.
        workdir: RepoRelPath,
        /// Failing component prefix or path.
        at: RepoRelPath,
    },
    /// Proper ancestor of a closure member was not a real directory.
    #[error("closure entry `{entry}` has non-directory ancestor `{ancestor}`")]
    NonDirectoryAncestor {
        /// Closure member path.
        entry: RepoRelPath,
        /// Ancestor path that was not `EntryKind::Dir`.
        ancestor: RepoRelPath,
    },
    /// Symlink target was absolute, empty, touched `.git`, escaped root, or
    /// exceeded hop limit.
    #[error("unsafe symlink `{symlink}` -> {target:?}: {reason}")]
    UnsafeSymlink {
        /// Symlink path.
        symlink: RepoRelPath,
        /// Raw symlink target.
        target: String,
        /// Rejection reason.
        reason: String,
    },
    /// Symlink hop or final resolved target escaped the declared source
    /// closure.
    #[error("symlink `{symlink}` resolved through `{escaped_path}` outside declared closure")]
    SymlinkEscapesClosure {
        /// Symlink path inside `closure`.
        symlink: RepoRelPath,
        /// Intermediate hop or final target outside `closure`.
        escaped_path: RepoRelPath,
    },
    /// `writable_dirs` entries overlapped each other, `closure`, or a resolved
    /// symlink hop/target.
    #[error("writable_dir `{writable_dir}` conflicts with `{conflict}`")]
    WritableDirConflict {
        /// Declared writable overlay directory.
        writable_dir: RepoRelPath,
        /// Conflicting writable dir, closure path, or symlink target.
        conflict: RepoRelPath,
    },
}

impl From<TypeError> for TreeError {
    fn from(err: TypeError) -> Self {
        Self::InvalidPattern(err.to_string())
    }
}

/// Read-only filesystem or bare-Git tree interface with `lstat` semantics.
pub trait SourceTree {
    /// Returns leaf metadata at `path` (`Ok(None)` if absent or if `path` is a
    /// real directory).
    fn entry(&self, path: &RepoRelPath) -> Result<Option<TreeEntry>, TreeError>;

    /// Lists immediate children of `dir` (`None` for repository root) without
    /// following symlinks.
    fn list_dir(&self, dir: Option<&RepoRelPath>) -> Result<Vec<(String, EntryKind)>, TreeError>;

    /// Reads raw bytes of the regular file at `path` (`lstat`, does not follow
    /// leaf symlinks).
    fn read_blob(&self, path: &RepoRelPath) -> Result<Vec<u8>, TreeError>;

    /// Returns all non-directory leaf paths in sorted order (`lstat`).
    fn all_paths(&self) -> Result<Vec<RepoRelPath>, TreeError>;

    /// Returns the SHA-256 digest of the regular file at `path`.
    fn blob_sha256(&self, path: &RepoRelPath) -> Result<Sha256Digest, TreeError> {
        Ok(Sha256Digest::hash_bytes(&self.read_blob(path)?))
    }

    /// Returns the `lstat` `EntryKind` at `path`, distinguishing real
    /// directories from leaf entries.
    fn kind_of(&self, path: &RepoRelPath) -> Result<Option<EntryKind>, TreeError> {
        if let Some(entry) = self.entry(path)? {
            return Ok(Some(match entry {
                TreeEntry::Regular { .. } => EntryKind::File,
                TreeEntry::Symlink { .. } => EntryKind::Symlink,
                TreeEntry::Gitlink { .. } => EntryKind::Gitlink,
                TreeEntry::Special => EntryKind::Special,
            }));
        }
        let parent = path.parent();
        let name = path.file_name();
        let children = self.list_dir(parent.as_ref())?;
        Ok(children
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, kind)| kind))
    }
}

type DirListingCache = HashMap<Option<RepoRelPath>, Vec<(String, EntryKind)>>;

/// Memoizing read-only wrapper around any [`SourceTree`] so multi-check config
/// validation hashes each regular file and walks each directory at most once.
pub struct CachingSourceTree<'a> {
    inner: &'a dyn SourceTree,
    all_paths: RefCell<Option<Vec<RepoRelPath>>>,
    entries: RefCell<HashMap<RepoRelPath, Option<TreeEntry>>>,
    dirs: RefCell<DirListingCache>,
    kinds: RefCell<HashMap<RepoRelPath, Option<EntryKind>>>,
    blob_hashes: RefCell<HashMap<RepoRelPath, Sha256Digest>>,
}

impl<'a> CachingSourceTree<'a> {
    /// Wraps `inner` with per-path metadata, directory-listing, and SHA-256
    /// memoization.
    pub fn new(inner: &'a dyn SourceTree) -> Self {
        Self {
            inner,
            all_paths: RefCell::new(None),
            entries: RefCell::new(HashMap::new()),
            dirs: RefCell::new(HashMap::new()),
            kinds: RefCell::new(HashMap::new()),
            blob_hashes: RefCell::new(HashMap::new()),
        }
    }
}

impl SourceTree for CachingSourceTree<'_> {
    fn entry(&self, path: &RepoRelPath) -> Result<Option<TreeEntry>, TreeError> {
        if let Some(cached) = self.entries.borrow().get(path) {
            return Ok(cached.clone());
        }
        let val = self.inner.entry(path)?;
        self.entries.borrow_mut().insert(path.clone(), val.clone());
        Ok(val)
    }

    fn list_dir(&self, dir: Option<&RepoRelPath>) -> Result<Vec<(String, EntryKind)>, TreeError> {
        let key = dir.cloned();
        if let Some(cached) = self.dirs.borrow().get(&key) {
            return Ok(cached.clone());
        }
        let val = self.inner.list_dir(dir)?;
        self.dirs.borrow_mut().insert(key, val.clone());
        Ok(val)
    }

    fn read_blob(&self, path: &RepoRelPath) -> Result<Vec<u8>, TreeError> {
        let bytes = self.inner.read_blob(path)?;
        self.blob_hashes
            .borrow_mut()
            .entry(path.clone())
            .or_insert_with(|| Sha256Digest::hash_bytes(&bytes));
        Ok(bytes)
    }

    fn blob_sha256(&self, path: &RepoRelPath) -> Result<Sha256Digest, TreeError> {
        if let Some(&h) = self.blob_hashes.borrow().get(path) {
            return Ok(h);
        }
        let h = self.inner.blob_sha256(path)?;
        self.blob_hashes.borrow_mut().insert(path.clone(), h);
        Ok(h)
    }

    fn all_paths(&self) -> Result<Vec<RepoRelPath>, TreeError> {
        if let Some(ref cached) = *self.all_paths.borrow() {
            return Ok(cached.clone());
        }
        let val = self.inner.all_paths()?;
        *self.all_paths.borrow_mut() = Some(val.clone());
        Ok(val)
    }

    fn kind_of(&self, path: &RepoRelPath) -> Result<Option<EntryKind>, TreeError> {
        if let Some(&cached) = self.kinds.borrow().get(path) {
            return Ok(cached);
        }
        let val = if let Some(entry) = self.entry(path)? {
            Some(match entry {
                TreeEntry::Regular { .. } => EntryKind::File,
                TreeEntry::Symlink { .. } => EntryKind::Symlink,
                TreeEntry::Gitlink { .. } => EntryKind::Gitlink,
                TreeEntry::Special => EntryKind::Special,
            })
        } else {
            let parent = path.parent();
            let name = path.file_name();
            let children = self.list_dir(parent.as_ref())?;
            children
                .into_iter()
                .find(|(n, _)| n == name)
                .map(|(_, kind)| kind)
        };
        self.kinds.borrow_mut().insert(path.clone(), val);
        Ok(val)
    }
}

/// Deterministic in-memory `SourceTree` for unit, property, and differential
/// testing.
#[derive(Debug, Clone, Default)]
pub struct InMemoryTree {
    files: BTreeMap<RepoRelPath, (bool, Vec<u8>)>,
    symlinks: BTreeMap<RepoRelPath, String>,
    gitlinks: BTreeMap<RepoRelPath, GitOid>,
    specials: BTreeSet<RepoRelPath>,
    explicit_empty_dirs: BTreeSet<RepoRelPath>,
}

impl InMemoryTree {
    /// Creates an empty `InMemoryTree`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or overwrites a regular non-executable (`100644`) file.
    pub fn insert_file(&mut self, path: &str, contents: impl Into<Vec<u8>>) {
        let p = RepoRelPath::new(path).expect("test path must be valid RepoRelPath");
        self.symlinks.remove(&p);
        self.gitlinks.remove(&p);
        self.specials.remove(&p);
        self.files.insert(p, (false, contents.into()));
    }

    /// Inserts or overwrites an executable (`100755`) regular file.
    pub fn insert_executable(&mut self, path: &str, contents: impl Into<Vec<u8>>) {
        let p = RepoRelPath::new(path).expect("test path must be valid RepoRelPath");
        self.symlinks.remove(&p);
        self.gitlinks.remove(&p);
        self.specials.remove(&p);
        self.files.insert(p, (true, contents.into()));
    }

    /// Inserts or overwrites a symbolic link (`120000`).
    pub fn insert_symlink(&mut self, path: &str, target: impl Into<String>) {
        let p = RepoRelPath::new(path).expect("test path must be valid RepoRelPath");
        self.files.remove(&p);
        self.gitlinks.remove(&p);
        self.specials.remove(&p);
        self.symlinks.insert(p, target.into());
    }

    /// Inserts a submodule gitlink (`160000`).
    pub fn insert_gitlink(&mut self, path: &str, oid: GitOid) {
        let p = RepoRelPath::new(path).expect("test path must be valid RepoRelPath");
        self.files.remove(&p);
        self.symlinks.remove(&p);
        self.specials.remove(&p);
        self.gitlinks.insert(p, oid);
    }

    /// Inserts a special node (FIFO/device/socket).
    pub fn insert_special(&mut self, path: &str) {
        let p = RepoRelPath::new(path).expect("test path must be valid RepoRelPath");
        self.files.remove(&p);
        self.symlinks.remove(&p);
        self.gitlinks.remove(&p);
        self.specials.insert(p);
    }

    /// Inserts an explicit empty directory (useful for Cargo glob error tests).
    pub fn insert_empty_dir(&mut self, path: &str) {
        let p = RepoRelPath::new(path).expect("test path must be valid RepoRelPath");
        self.explicit_empty_dirs.insert(p);
    }

    /// Removes a leaf entry if present.
    pub fn remove(&mut self, path: &str) {
        if let Ok(p) = RepoRelPath::new(path) {
            self.files.remove(&p);
            self.symlinks.remove(&p);
            self.gitlinks.remove(&p);
            self.specials.remove(&p);
            self.explicit_empty_dirs.remove(&p);
        }
    }

    fn all_leaf_kinds(&self) -> BTreeMap<RepoRelPath, EntryKind> {
        let mut out = BTreeMap::new();
        for k in self.files.keys() {
            out.insert(k.clone(), EntryKind::File);
        }
        for k in self.symlinks.keys() {
            out.insert(k.clone(), EntryKind::Symlink);
        }
        for k in self.gitlinks.keys() {
            out.insert(k.clone(), EntryKind::Gitlink);
        }
        for k in &self.specials {
            out.insert(k.clone(), EntryKind::Special);
        }
        out
    }
}

impl SourceTree for InMemoryTree {
    fn entry(&self, path: &RepoRelPath) -> Result<Option<TreeEntry>, TreeError> {
        if let Some((executable, _)) = self.files.get(path) {
            return Ok(Some(TreeEntry::Regular {
                executable: *executable,
            }));
        }
        if let Some(target) = self.symlinks.get(path) {
            return Ok(Some(TreeEntry::Symlink {
                target: target.clone(),
            }));
        }
        if let Some(oid) = self.gitlinks.get(path) {
            return Ok(Some(TreeEntry::Gitlink { oid: *oid }));
        }
        if self.specials.contains(path) {
            return Ok(Some(TreeEntry::Special));
        }
        Ok(None)
    }

    fn list_dir(&self, dir: Option<&RepoRelPath>) -> Result<Vec<(String, EntryKind)>, TreeError> {
        let mut children: BTreeMap<String, EntryKind> = BTreeMap::new();
        let prefix = dir.map(|d| format!("{}/", d.as_str()));

        let mut register_rel = |rel: &str, leaf_kind: EntryKind| {
            if let Some((first_seg, _rest)) = rel.split_once('/') {
                children
                    .entry(first_seg.to_owned())
                    .or_insert(EntryKind::Dir);
            } else if !rel.is_empty() {
                children.insert(rel.to_owned(), leaf_kind);
            }
        };

        for (p, kind) in self.all_leaf_kinds() {
            match &prefix {
                None => register_rel(p.as_str(), kind),
                Some(pre) => {
                    if let Some(rel) = p.as_str().strip_prefix(pre) {
                        register_rel(rel, kind);
                    }
                }
            }
        }
        for d in &self.explicit_empty_dirs {
            match &prefix {
                None => register_rel(d.as_str(), EntryKind::Dir),
                Some(pre) => {
                    if let Some(rel) = d.as_str().strip_prefix(pre) {
                        register_rel(rel, EntryKind::Dir);
                    }
                }
            }
        }
        Ok(children.into_iter().collect())
    }

    fn read_blob(&self, path: &RepoRelPath) -> Result<Vec<u8>, TreeError> {
        self.files
            .get(path)
            .map(|(_, bytes)| bytes.clone())
            .ok_or_else(|| TreeError::MissingPath(path.clone()))
    }

    fn all_paths(&self) -> Result<Vec<RepoRelPath>, TreeError> {
        Ok(self.all_leaf_kinds().into_keys().collect())
    }
}

/// Resolves a path inside a confined root (`""`) using POSIX `path_resolution`
/// symlink-expansion semantics (`lookup_symlink` returns `Some(target)` iff the
/// given relative path is itself a symlink).
///
/// Records every intermediate resolved symlink hop and returns
/// `(hops, final_path)`, failing closed on absolute symlinks, empty targets,
/// NUL/backslash bytes, `.git` components, root escapes (`..` at root), or
/// chains exceeding `MAX_SYMLINK_HOPS`.
pub fn resolve_confined_symlink_chain<F>(
    origin: &RepoRelPath,
    mut lookup_symlink: F,
) -> Result<(Vec<RepoRelPath>, RepoRelPath), TreeError>
where
    F: FnMut(&RepoRelPath) -> Result<Option<String>, TreeError>,
{
    let mut stack: Vec<String> = Vec::new();
    let mut queue: Vec<String> = origin
        .as_str()
        .split('/')
        .rev()
        .map(str::to_owned)
        .collect();
    let mut hops_count = 0usize;
    let mut recorded_hops: Vec<RepoRelPath> = Vec::new();

    while let Some(seg) = queue.pop() {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".git" {
            return Err(TreeError::UnsafeSymlink {
                symlink: origin.clone(),
                target: seg,
                reason: "touches .git".to_owned(),
            });
        }
        if seg == ".." {
            if stack.pop().is_none() {
                return Err(TreeError::UnsafeSymlink {
                    symlink: origin.clone(),
                    target: "..".to_owned(),
                    reason: "escapes confined root".to_owned(),
                });
            }
            continue;
        }
        stack.push(seg);
        let cur_rel = RepoRelPath::new(&stack.join("/"))?;
        if let Some(raw_target) = lookup_symlink(&cur_rel)? {
            hops_count += 1;
            if hops_count > MAX_SYMLINK_HOPS {
                return Err(TreeError::UnsafeSymlink {
                    symlink: origin.clone(),
                    target: raw_target,
                    reason: format!("symlink chain exceeded {MAX_SYMLINK_HOPS} hops (cycle)"),
                });
            }
            if raw_target.is_empty()
                || raw_target.starts_with('/')
                || raw_target.contains('\0')
                || raw_target.contains('\\')
            {
                return Err(TreeError::UnsafeSymlink {
                    symlink: cur_rel,
                    target: raw_target,
                    reason: "symlink target must be non-empty relative POSIX without NUL/backslash"
                        .to_owned(),
                });
            }
            // Pop the symlink component itself; its target resolves relative to
            // its parent directory.
            stack.pop();
            let target_segs: Vec<&str> = raw_target.split('/').collect();
            // Compute the lexical target of this single hop (before expanding
            // remaining trailing components) so intermediate hop confinement is
            // checked even if `..` appears later in `queue`.
            let mut hop_preview = stack.clone();
            for &tseg in &target_segs {
                if tseg.is_empty() || tseg == "." {
                    continue;
                }
                if tseg == ".git" {
                    return Err(TreeError::UnsafeSymlink {
                        symlink: cur_rel,
                        target: raw_target,
                        reason: "symlink target touches .git".to_owned(),
                    });
                }
                if tseg == ".." {
                    if hop_preview.pop().is_none() {
                        return Err(TreeError::UnsafeSymlink {
                            symlink: cur_rel,
                            target: raw_target,
                            reason: "symlink target escapes confined root".to_owned(),
                        });
                    }
                } else {
                    hop_preview.push(tseg.to_owned());
                }
            }
            if !hop_preview.is_empty() {
                recorded_hops.push(RepoRelPath::new(&hop_preview.join("/"))?);
            }
            for &tseg in target_segs.iter().rev() {
                queue.push(tseg.to_owned());
            }
        }
    }

    if stack.is_empty() {
        // Symlink resolved to the confined root directory `""` itself (e.g.
        // `sub/link -> ..`). Represent root resolution rejected for source
        // closures unless `origin` is allowed inside a confined cache dir.
        return Err(TreeError::UnsafeSymlink {
            symlink: origin.clone(),
            target: ".".to_owned(),
            reason: "symlink resolves to repository/cache root directory".to_owned(),
        });
    }
    let final_path = RepoRelPath::new(&stack.join("/"))?;
    Ok((recorded_hops, final_path))
}

/// Resolves `path` in `tree` following in-repo symlinks and returns the final
/// `(RepoRelPath, Option<EntryKind>)`.
pub fn resolve_in_tree(
    tree: &dyn SourceTree,
    path: &RepoRelPath,
) -> Result<(Vec<RepoRelPath>, RepoRelPath, Option<EntryKind>), TreeError> {
    let (hops, final_path) =
        resolve_confined_symlink_chain(path, |cand| match tree.entry(cand)? {
            Some(TreeEntry::Symlink { target }) => Ok(Some(target)),
            Some(TreeEntry::Gitlink { .. }) => Err(TreeError::ForbiddenEntryKind {
                path: cand.clone(),
                kind: EntryKind::Gitlink,
            }),
            Some(TreeEntry::Special) => Err(TreeError::ForbiddenEntryKind {
                path: cand.clone(),
                kind: EntryKind::Special,
            }),
            Some(TreeEntry::Regular { .. }) | None => Ok(None),
        })?;
    let kind = tree.kind_of(&final_path)?;
    Ok((hops, final_path, kind))
}

fn is_in_closure_or_ancestor(
    path: &RepoRelPath,
    closure: &BTreeSet<RepoRelPath>,
    closure_ancestors: &BTreeSet<RepoRelPath>,
) -> bool {
    closure.contains(path) || closure_ancestors.contains(path)
}

/// Proof-carrying validated source closure ready for `TreeMerkle` hashing or
/// `/work` materialization.
#[derive(Debug, Clone)]
pub struct ValidatedSourceClosure {
    entries: BTreeMap<RepoRelPath, MerkleEntry>,
    merkle: Sha256Digest,
    resolved_symlink_paths: BTreeSet<RepoRelPath>,
}

impl ValidatedSourceClosure {
    /// Returns the cached `TreeMerkle` over the validated closure entries.
    pub const fn merkle_digest(&self) -> Sha256Digest {
        self.merkle
    }

    /// Returns the validated closure paths.
    pub fn entries(&self) -> &BTreeMap<RepoRelPath, MerkleEntry> {
        &self.entries
    }

    /// Returns all intermediate and final symlink hop paths visited.
    pub fn resolved_symlink_paths(&self) -> &BTreeSet<RepoRelPath> {
        &self.resolved_symlink_paths
    }
}

/// Validates a check, cache, or image build-context source closure before
/// `TreeMerkle` computation, `/work` staging, or `run-local --native`.
///
/// Enforces:
/// 1. `workdir` (and all proper directory prefixes of `workdir`) is a real
///    `EntryKind::Dir` directory (`0` symlinks).
/// 2. `writable_dirs` are pairwise prefix-free disjoint.
/// 3. Every `p ∈ closure` has real `EntryKind::Dir` proper ancestors and is a
///    `Regular` or `Symlink` entry (`0` `Gitlink` or `Special` nodes).
/// 4. Every symlink `p ∈ closure` resolves exclusively through intermediate
///    hops and final target `q` inside `closure` (member or proper ancestor
///    directory of a member in `closure`) without touching `.git`, escaping
///    root, or cycling; and if `q` is a real directory in `tree`, every leaf
///    under `q/**` in `tree` must also belong to `closure` so symlinking a
///    partially included directory cannot expose undeclared files in `--native`.
/// 5. Every `w ∈ writable_dirs` is prefix-free disjoint from both `closure`
///    members and every resolved symlink hop/target.
pub fn validate_source_closure(
    tree: &dyn SourceTree,
    closure: &BTreeSet<RepoRelPath>,
    workdir: Option<&RepoRelPath>,
    writable_dirs: &[RepoRelPath],
) -> Result<ValidatedSourceClosure, TreeError> {
    for (i, d1) in writable_dirs.iter().enumerate() {
        for d2 in &writable_dirs[i + 1..] {
            if !d1.is_prefix_disjoint(d2) {
                return Err(TreeError::WritableDirConflict {
                    writable_dir: d1.clone(),
                    conflict: d2.clone(),
                });
            }
        }
    }

    if let Some(wd) = workdir {
        for anc in wd.proper_ancestors() {
            if tree.kind_of(&anc)? != Some(EntryKind::Dir) {
                return Err(TreeError::InvalidWorkdir {
                    workdir: wd.clone(),
                    at: anc,
                });
            }
        }
        if tree.kind_of(wd)? != Some(EntryKind::Dir) {
            return Err(TreeError::InvalidWorkdir {
                workdir: wd.clone(),
                at: wd.clone(),
            });
        }
    }

    let mut closure_ancestors = BTreeSet::new();
    for p in closure {
        for anc in p.proper_ancestors() {
            closure_ancestors.insert(anc);
        }
    }
    for anc in &closure_ancestors {
        if tree.kind_of(anc)? != Some(EntryKind::Dir) {
            let offending = closure
                .iter()
                .find(|p| anc.is_prefix_of(p))
                .cloned()
                .unwrap_or_else(|| anc.clone());
            return Err(TreeError::NonDirectoryAncestor {
                entry: offending,
                ancestor: anc.clone(),
            });
        }
    }

    let mut all_tree_paths_lazy: Option<Vec<RepoRelPath>> = None;
    let mut merkle_entries = BTreeMap::new();
    let mut all_resolved_hops = BTreeSet::new();

    for p in closure {
        for wd in writable_dirs {
            if !wd.is_prefix_disjoint(p) {
                return Err(TreeError::WritableDirConflict {
                    writable_dir: wd.clone(),
                    conflict: p.clone(),
                });
            }
        }
        let Some(entry) = tree.entry(p)? else {
            return Err(TreeError::MissingPath(p.clone()));
        };
        match entry {
            TreeEntry::Regular { executable } => {
                let sha256 = tree.blob_sha256(p)?;
                merkle_entries.insert(p.clone(), MerkleEntry::Regular { executable, sha256 });
            }
            TreeEntry::Symlink { target } => {
                let (hops, final_q, final_kind) = resolve_in_tree(tree, p)?;
                for hop in hops.iter().chain(std::iter::once(&final_q)) {
                    if !is_in_closure_or_ancestor(hop, closure, &closure_ancestors) {
                        return Err(TreeError::SymlinkEscapesClosure {
                            symlink: p.clone(),
                            escaped_path: hop.clone(),
                        });
                    }
                    for wd in writable_dirs {
                        if !wd.is_prefix_disjoint(hop) {
                            return Err(TreeError::WritableDirConflict {
                                writable_dir: wd.clone(),
                                conflict: hop.clone(),
                            });
                        }
                    }
                    all_resolved_hops.insert(hop.clone());
                }
                match final_kind {
                    Some(EntryKind::File) => {}
                    Some(EntryKind::Dir) => {
                        let all_paths = match &all_tree_paths_lazy {
                            Some(v) => v,
                            None => {
                                all_tree_paths_lazy = Some(tree.all_paths()?);
                                all_tree_paths_lazy.as_ref().expect("just populated")
                            }
                        };
                        for tp in all_paths {
                            if final_q.is_prefix_of(tp) && !closure.contains(tp) {
                                return Err(TreeError::SymlinkEscapesClosure {
                                    symlink: p.clone(),
                                    escaped_path: tp.clone(),
                                });
                            }
                        }
                    }
                    Some(EntryKind::Gitlink) => {
                        return Err(TreeError::ForbiddenEntryKind {
                            path: final_q,
                            kind: EntryKind::Gitlink,
                        });
                    }
                    Some(EntryKind::Special) => {
                        return Err(TreeError::ForbiddenEntryKind {
                            path: final_q,
                            kind: EntryKind::Special,
                        });
                    }
                    Some(EntryKind::Symlink) | None => {
                        return Err(TreeError::SymlinkEscapesClosure {
                            symlink: p.clone(),
                            escaped_path: final_q,
                        });
                    }
                }
                merkle_entries.insert(p.clone(), MerkleEntry::Symlink { target });
            }
            TreeEntry::Gitlink { .. } => {
                return Err(TreeError::ForbiddenEntryKind {
                    path: p.clone(),
                    kind: EntryKind::Gitlink,
                });
            }
            TreeEntry::Special => {
                return Err(TreeError::ForbiddenEntryKind {
                    path: p.clone(),
                    kind: EntryKind::Special,
                });
            }
        }
    }

    let merkle = compute_tree_merkle(&merkle_entries);
    Ok(ValidatedSourceClosure {
        entries: merkle_entries,
        merkle,
        resolved_symlink_paths: all_resolved_hops,
    })
}

/// Entry classification inside a confined cache directory or `.tar.zst` archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfinedEntry {
    /// Regular file (`100644` / `100755`) or internal hardlink.
    Regular,
    /// Real directory (`040000`).
    Dir,
    /// Symbolic link (`120000`) with raw target string.
    Symlink {
        /// Raw symlink target string.
        target: String,
    },
    /// Gitlink (`160000`), forbidden in confined directories.
    Gitlink,
    /// Device, FIFO, socket, or setuid/setgid node, forbidden.
    Special,
}

/// Validates all entries of a cache directory (before `pack` or `hydrate`)
/// using the same cycle-safe multi-hop symlink resolver as source closures.
///
/// Rejects `.git` components (enforced by `RepoRelPath` + target walk),
/// `Gitlink`, `Special`, absolute symlinks, cycles, and any single- or
/// multi-hop relative symlink chain (`x/y -> ..` + `z -> x/y/../..`) escaping
/// the confined directory root.
pub fn validate_confined_dir(
    entries: &BTreeMap<RepoRelPath, ConfinedEntry>,
) -> Result<(), TreeError> {
    for (p, entry) in entries {
        match entry {
            ConfinedEntry::Regular | ConfinedEntry::Dir => {}
            ConfinedEntry::Gitlink => {
                return Err(TreeError::ForbiddenEntryKind {
                    path: p.clone(),
                    kind: EntryKind::Gitlink,
                });
            }
            ConfinedEntry::Special => {
                return Err(TreeError::ForbiddenEntryKind {
                    path: p.clone(),
                    kind: EntryKind::Special,
                });
            }
            ConfinedEntry::Symlink { .. } => {}
        }
        // Verify that no proper ancestor of `p` is itself a symlink that
        // escapes the confined root when resolving `p`.
        for anc in p.proper_ancestors() {
            if matches!(entries.get(&anc), Some(ConfinedEntry::Symlink { .. })) {
                validate_confined_symlink_path(&anc, entries)?;
            }
        }
        if matches!(entry, ConfinedEntry::Symlink { .. }) {
            validate_confined_symlink_path(p, entries)?;
        }
    }
    Ok(())
}

fn validate_confined_symlink_path(
    origin: &RepoRelPath,
    entries: &BTreeMap<RepoRelPath, ConfinedEntry>,
) -> Result<(), TreeError> {
    // Allow a symlink inside a cache dir to resolve to the confined root `""`
    // (e.g. `sub/root_link -> ..`) ONLY if no `..` ever pops past root; still
    // trace multi-hop chains when chained by another symlink (`z -> sub/root_link/..`).
    let mut stack: Vec<String> = Vec::new();
    let mut queue: Vec<String> = origin
        .as_str()
        .split('/')
        .rev()
        .map(str::to_owned)
        .collect();
    let mut hops_count = 0usize;

    while let Some(seg) = queue.pop() {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".git" {
            return Err(TreeError::UnsafeSymlink {
                symlink: origin.clone(),
                target: seg,
                reason: "touches .git".to_owned(),
            });
        }
        if seg == ".." {
            if stack.pop().is_none() {
                return Err(TreeError::UnsafeSymlink {
                    symlink: origin.clone(),
                    target: "..".to_owned(),
                    reason: "escapes confined cache root".to_owned(),
                });
            }
            continue;
        }
        stack.push(seg);
        let cur_rel = RepoRelPath::new(&stack.join("/"))?;
        if let Some(ConfinedEntry::Symlink { target: raw_target }) = entries.get(&cur_rel) {
            hops_count += 1;
            if hops_count > MAX_SYMLINK_HOPS {
                return Err(TreeError::UnsafeSymlink {
                    symlink: origin.clone(),
                    target: raw_target.clone(),
                    reason: format!("symlink chain exceeded {MAX_SYMLINK_HOPS} hops (cycle)"),
                });
            }
            if raw_target.is_empty()
                || raw_target.starts_with('/')
                || raw_target.contains('\0')
                || raw_target.contains('\\')
            {
                return Err(TreeError::UnsafeSymlink {
                    symlink: cur_rel,
                    target: raw_target.clone(),
                    reason: "symlink target must be non-empty relative POSIX without NUL/backslash"
                        .to_owned(),
                });
            }
            stack.pop();
            let target_segs: Vec<&str> = raw_target.split('/').collect();
            let mut preview = stack.clone();
            for &tseg in &target_segs {
                if tseg.is_empty() || tseg == "." {
                    continue;
                }
                if tseg == ".git" {
                    return Err(TreeError::UnsafeSymlink {
                        symlink: cur_rel,
                        target: raw_target.clone(),
                        reason: "symlink target touches .git".to_owned(),
                    });
                }
                if tseg == ".." {
                    if preview.pop().is_none() {
                        return Err(TreeError::UnsafeSymlink {
                            symlink: cur_rel,
                            target: raw_target.clone(),
                            reason: "symlink target escapes confined cache root".to_owned(),
                        });
                    }
                } else {
                    preview.push(tseg.to_owned());
                }
            }
            for &tseg in target_segs.iter().rev() {
                queue.push(tseg.to_owned());
            }
        }
    }
    Ok(())
}

/// Precompiled single-pattern POSIX glob matcher backed by `globset`'s linear-
/// time automaton (`*` confined within `/`, `**` matching zero or more path
/// segments including dotfiles, backslashes and `{...}` alternation rejected).
#[derive(Debug, Clone)]
pub struct SelectorGlob(GlobMatcher);

fn parse_selector_glob_ast(raw: &str) -> Result<Glob, TreeError> {
    if raw.is_empty()
        || raw.starts_with('/')
        || raw.ends_with('/')
        || raw.contains('\0')
        || raw.contains('\\')
        || raw.contains('{')
        || raw.contains('}')
    {
        return Err(TreeError::InvalidPattern(format!(
            "invalid selector glob {raw:?}"
        )));
    }
    for seg in raw.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." || seg == ".git" {
            return Err(TreeError::InvalidPattern(format!(
                "forbidden segment `{seg}` in selector glob {raw:?}"
            )));
        }
    }
    GlobBuilder::new(raw)
        .literal_separator(true)
        .backslash_escape(false)
        .build()
        .map_err(|e| TreeError::InvalidPattern(format!("glob {raw:?}: {e}")))
}

/// Compiles a normalized POSIX glob pattern for `InputSelector::Glob`.
pub fn compile_selector_glob(raw: &str) -> Result<SelectorGlob, TreeError> {
    Ok(SelectorGlob(
        parse_selector_glob_ast(raw)?.compile_matcher(),
    ))
}

/// Compiles a slice of normalized POSIX glob patterns into a single simultaneous
/// `GlobSet` automaton.
pub fn compile_selector_globset(globs: &[String]) -> Result<GlobSet, TreeError> {
    let mut builder = GlobSetBuilder::new();
    for raw in globs {
        builder.add(parse_selector_glob_ast(raw)?);
    }
    builder
        .build()
        .map_err(|e| TreeError::InvalidPattern(format!("globset build failed: {e}")))
}

/// Matches `path` against a compiled `SelectorGlob` (`*` does not cross `/`,
/// `**` recurses across directories including dotfiles).
pub fn selector_glob_matches(pattern: &SelectorGlob, path: &RepoRelPath) -> bool {
    pattern.0.is_match(path.as_str())
}

/// Evaluates an `include` minus `exclude` glob set against `all_paths` using
/// linear-time `GlobSet` automata.
pub fn filter_paths_by_globs(
    all_paths: &[RepoRelPath],
    include: &[String],
    exclude: &[String],
) -> Result<BTreeSet<RepoRelPath>, TreeError> {
    let inc_set = compile_selector_globset(include)?;
    let exc_set = compile_selector_globset(exclude)?;
    let mut out = BTreeSet::new();
    for p in all_paths {
        let s = p.as_str();
        if inc_set.is_match(s) && !exc_set.is_match(s) {
            out.insert(p.clone());
        }
    }
    Ok(out)
}
