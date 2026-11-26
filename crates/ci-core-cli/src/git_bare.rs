//! Hardened bare-Git object store (`BareGitTree`), local developer worktree
//! (`LocalWorktree`), iterative deepening, bare `git merge-tree --write-tree`
//! commit-slice replay, and symmetric `CODEOWNERS` error lookup.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use ci_core_model::config::ChecksConfig;
use ci_core_model::store::{GitHubApi, MergeMethod, MergeQueueEntry};
use ci_core_model::tcb::CommitSliceReplayer;
use ci_core_model::tree::{EntryKind, SourceTree, TreeEntry, TreeError};
use ci_core_model::types::{CallerMode, GitOid, RepoRelPath};
use thiserror::Error;

/// Errors returned by hardened Git operations.
#[derive(Debug, Error)]
pub enum GitError {
    /// Failed to spawn or complete a `git` command.
    #[error("git command `{cmd}` failed: {reason}")]
    Command {
        /// Invoked git subcommand summary.
        cmd: String,
        /// Exit code and stderr output.
        reason: String,
    },
    /// Malformed Git object or tree output.
    #[error("malformed git output: {0}")]
    Parse(String),
    /// Underlying `TreeError`.
    #[error(transparent)]
    Tree(#[from] TreeError),
}

/// Hardened bare Git repository wrapper (`$RUNNER_TEMP/ci-core-bare.git` or an
/// existing `.git` object store).
///
/// Disables system/global gitconfigs, hooks, fsmonitor, smudge filters,
/// autocrlf, external diffs, and `ext::` remotes on every invocation, and
/// passes optional HTTP Basic credentials via ephemeral command-line `-c`
/// arguments rather than persisting them into `config`.
#[derive(Debug, Clone)]
pub struct HardenedBareGit {
    git_dir: PathBuf,
    remote_url: Option<String>,
    auth_token: Option<String>,
}

impl HardenedBareGit {
    /// Initializes a new bare repository at `git_dir` (creating parent
    /// directories if needed).
    pub fn init_bare(
        git_dir: impl Into<PathBuf>,
        remote_url: Option<String>,
        auth_token: Option<String>,
    ) -> Result<Self, GitError> {
        let dir = git_dir.into();
        if !dir.join("HEAD").exists() {
            fs::create_dir_all(&dir).map_err(|e| GitError::Command {
                cmd: "mkdir bare git".to_owned(),
                reason: e.to_string(),
            })?;
            let out = Self::base_command(&dir)
                .args(["init", "--bare", "--quiet"])
                .output()
                .map_err(|e| GitError::Command {
                    cmd: "git init --bare".to_owned(),
                    reason: e.to_string(),
                })?;
            if !out.status.success() {
                return Err(GitError::Command {
                    cmd: "git init --bare".to_owned(),
                    reason: String::from_utf8_lossy(&out.stderr).into_owned(),
                });
            }
        }
        Ok(Self {
            git_dir: dir,
            remote_url,
            auth_token,
        })
    }

    /// Wraps an existing `.git` directory or bare repository read-only.
    pub fn open_existing(git_dir: impl Into<PathBuf>) -> Result<Self, GitError> {
        let dir = git_dir.into();
        if !dir.exists() {
            return Err(GitError::Command {
                cmd: "open_existing".to_owned(),
                reason: format!("git_dir `{}` does not exist", dir.display()),
            });
        }
        Ok(Self {
            git_dir: dir,
            remote_url: None,
            auth_token: None,
        })
    }

    /// Path to the bare `.git` directory.
    pub fn git_dir(&self) -> &Path {
        &self.git_dir
    }

    fn base_command(git_dir: &Path) -> Command {
        let mut cmd = Command::new("git");
        cmd.env_clear();
        for passthrough in [
            "PATH",
            "HOME",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        ] {
            if let Ok(v) = std::env::var(passthrough) {
                cmd.env(passthrough, v);
            }
        }
        cmd.env("GIT_DIR", git_dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_LFS_SKIP_SMUDGE", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args([
                "-c",
                "core.bare=true",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.autocrlf=false",
                "-c",
                "gc.auto=0",
                "-c",
                "gc.autoDetach=false",
                "-c",
                "maintenance.auto=false",
                "-c",
                "diff.external=",
                "-c",
                "protocol.ext.allow=never",
            ]);
        cmd
    }

    /// Executes a local (non-network) `git` command against `self.git_dir`.
    pub fn run_local(&self, args: &[&str]) -> Result<Vec<u8>, GitError> {
        let out = Self::base_command(&self.git_dir)
            .args(args)
            .output()
            .map_err(|e| GitError::Command {
                cmd: format!("git {}", args.join(" ")),
                reason: e.to_string(),
            })?;
        if !out.status.success() {
            return Err(GitError::Command {
                cmd: format!("git {}", args.join(" ")),
                reason: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            });
        }
        Ok(out.stdout)
    }

    fn is_transient_shallow_race(stderr: &str) -> bool {
        stderr.contains("shallow file has changed since we read it")
            || (stderr.contains("shallow.lock") && stderr.contains("Unable to create"))
    }

    fn auth_header_arg(&self, remote: &str) -> Option<String> {
        self.auth_token
            .as_deref()
            .filter(|tok| !tok.is_empty() && remote.starts_with("https://github.com/"))
            .map(|tok| {
                let basic = base64::engine::general_purpose::STANDARD
                    .encode(format!("x-access-token:{tok}"));
                format!("http.https://github.com/.extraheader=AUTHORIZATION: basic {basic}")
            })
    }

    fn resolve_remote_ref_oid(&self, remote_ref: &str) -> Result<GitOid, GitError> {
        let remote = self
            .remote_url
            .as_deref()
            .ok_or_else(|| GitError::Command {
                cmd: "git ls-remote".to_owned(),
                reason: "no remote_url configured on HardenedBareGit".to_owned(),
            })?;
        let mut cmd = Self::base_command(&self.git_dir);
        if let Some(hdr) = self.auth_header_arg(remote) {
            cmd.args(["-c", &hdr]);
        }
        cmd.args(["ls-remote", "--", remote, remote_ref]);
        let out = cmd.output().map_err(|e| GitError::Command {
            cmd: format!("git ls-remote {remote_ref}"),
            reason: e.to_string(),
        })?;
        if !out.status.success() {
            return Err(GitError::Command {
                cmd: format!("git ls-remote {remote_ref}"),
                reason: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            });
        }
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some((hex, rname)) = line.trim().split_once('\t')
                && rname == remote_ref
            {
                return GitOid::from_hex(hex).map_err(|e| GitError::Parse(e.to_string()));
            }
        }
        Err(GitError::Command {
            cmd: format!("git ls-remote {remote_ref}"),
            reason: format!("remote ref `{remote_ref}` not found"),
        })
    }

    fn run_network_fetch(&self, refspec: &str, depth: Option<u32>) -> Result<(), GitError> {
        let remote = self
            .remote_url
            .as_deref()
            .ok_or_else(|| GitError::Command {
                cmd: "git fetch".to_owned(),
                reason: "no remote_url configured on HardenedBareGit".to_owned(),
            })?;
        let basic_header = self.auth_header_arg(remote);

        const BACKOFF_MS: [u64; 3] = [50, 150, 400];
        let mut last_reason = String::new();
        for delay_ms in BACKOFF_MS
            .iter()
            .copied()
            .map(Some)
            .chain(std::iter::once(None))
        {
            let mut cmd = Self::base_command(&self.git_dir);
            cmd.env("LC_ALL", "C");
            cmd.env("LC_MESSAGES", "C");
            if let Some(ref hdr) = basic_header {
                cmd.args(["-c", hdr]);
            }
            cmd.args(["fetch", "--no-tags", "--no-recurse-submodules"]);
            if let Some(d) = depth {
                cmd.arg(format!("--depth={d}"));
            }
            cmd.args([remote, refspec]);
            let out = cmd.output().map_err(|e| GitError::Command {
                cmd: format!("git fetch {refspec}"),
                reason: e.to_string(),
            })?;
            if out.status.success() {
                return Ok(());
            }
            last_reason = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            if let Some(ms) = delay_ms
                && Self::is_transient_shallow_race(&last_reason)
            {
                std::thread::sleep(std::time::Duration::from_millis(ms));
                continue;
            }
            break;
        }
        Err(GitError::Command {
            cmd: format!("git fetch {refspec}"),
            reason: last_reason,
        })
    }

    /// Fetches an immutable commit OID with optional shallow `depth`.
    pub fn fetch_oid(&self, oid: &GitOid, depth: u32) -> Result<(), GitError> {
        self.run_network_fetch(&oid.to_hex(), Some(depth))
    }

    /// Fetches a named remote ref (such as `refs/heads/main`) into
    /// `local_ref` and returns its resolved `GitOid`.
    pub fn fetch_ref(
        &self,
        remote_ref: &str,
        local_ref: &str,
        depth: u32,
    ) -> Result<GitOid, GitError> {
        let spec = format!("+{remote_ref}:{local_ref}");
        match self.run_network_fetch(&spec, Some(depth)) {
            Ok(()) => self.rev_parse_oid(local_ref),
            Err(GitError::Command { ref reason, .. })
                if Self::is_transient_shallow_race(reason) =>
            {
                // Git's smart-HTTP `fetch-pack` child can update `$GIT_DIR/shallow`
                // before parent `git fetch` validates `shallow_stat` for `+src:dst`
                // ref updates on stacked shallow repos. Fallback to `ls-remote` +
                // refspec-free `fetch_oid` + `update-ref` avoids `store_updated_refs`
                // shallow re-stat failure while preserving exact ref resolution.
                let oid = self.resolve_remote_ref_oid(remote_ref)?;
                self.fetch_oid(&oid, depth)?;
                self.run_local(&["update-ref", local_ref, &oid.to_hex()])?;
                self.rev_parse_oid(local_ref)
            }
            Err(err) => Err(err),
        }
    }

    /// Iteratively deepens `tip` until `ancestor` is present and verified via
    /// `git merge-base --is-ancestor`, failing closed if the root commit is
    /// reached without establishing ancestry.
    pub fn ensure_ancestor_with_deepening(
        &self,
        ancestor: &GitOid,
        tip_ref_or_oid: &str,
    ) -> Result<(), GitError> {
        let tip_oid = match GitOid::from_hex(tip_ref_or_oid) {
            Ok(oid) => oid,
            Err(_) => self.rev_parse_oid(tip_ref_or_oid)?,
        };
        let mut depth = 32u32;
        loop {
            if self.object_exists(ancestor)
                && self.is_ancestor(&ancestor.to_hex(), &tip_oid.to_hex())?
            {
                return Ok(());
            }
            if self.remote_url.is_none() || depth > 65_536 {
                return Err(GitError::Command {
                    cmd: "ensure_ancestor".to_owned(),
                    reason: format!(
                        "`{ancestor}` is not a verified ancestor of `{tip_ref_or_oid}` (`{tip_oid}`)"
                    ),
                });
            }
            self.fetch_oid(&tip_oid, depth)?;
            depth = depth.saturating_mul(4);
        }
    }

    /// Iteratively deepens both `a` and `b` until `git merge-base` succeeds.
    pub fn merge_base_with_deepening(&self, a: &GitOid, b: &GitOid) -> Result<GitOid, GitError> {
        let mut depth = 32u32;
        loop {
            if let Ok(out) = self.run_local(&["merge-base", &a.to_hex(), &b.to_hex()]) {
                let s = String::from_utf8_lossy(&out).trim().to_owned();
                if let Ok(oid) = GitOid::from_hex(&s) {
                    return Ok(oid);
                }
            }
            if self.remote_url.is_none() || depth > 65_536 {
                return Err(GitError::Command {
                    cmd: "git merge-base".to_owned(),
                    reason: format!("failed to resolve merge-base between `{a}` and `{b}`"),
                });
            }
            self.fetch_oid(a, depth)?;
            self.fetch_oid(b, depth)?;
            depth = depth.saturating_mul(4);
        }
    }

    /// Returns `true` iff a remote is configured, so missing history can be
    /// fetched.
    pub const fn has_remote(&self) -> bool {
        self.remote_url.is_some()
    }

    /// Checks whether `oid` exists as a commit/object locally.
    pub fn object_exists(&self, oid: &GitOid) -> bool {
        self.run_local(&["cat-file", "-e", &format!("{oid}^{{commit}}")])
            .is_ok()
    }

    /// Runs `git merge-base --is-ancestor <anc> <desc>`.
    pub fn is_ancestor(&self, anc: &str, desc: &str) -> Result<bool, GitError> {
        let out = Self::base_command(&self.git_dir)
            .args(["merge-base", "--is-ancestor", anc, desc])
            .output()
            .map_err(|e| GitError::Command {
                cmd: "git merge-base --is-ancestor".to_owned(),
                reason: e.to_string(),
            })?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(GitError::Command {
                cmd: "git merge-base --is-ancestor".to_owned(),
                reason: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            }),
        }
    }

    /// Resolves `rev` to a 40-hex `GitOid`.
    pub fn rev_parse_oid(&self, rev: &str) -> Result<GitOid, GitError> {
        let out = self.run_local(&["rev-parse", "--verify", &format!("{rev}^{{commit}}")])?;
        let s = String::from_utf8_lossy(&out).trim().to_owned();
        GitOid::from_hex(&s).map_err(|e| GitError::Parse(e.to_string()))
    }

    /// Resolves `rev^{tree}` to its tree `GitOid`.
    pub fn commit_tree_oid(&self, commit: &GitOid) -> Result<GitOid, GitError> {
        let out = self.run_local(&["rev-parse", "--verify", &format!("{commit}^{{tree}}")])?;
        let s = String::from_utf8_lossy(&out).trim().to_owned();
        GitOid::from_hex(&s).map_err(|e| GitError::Parse(e.to_string()))
    }

    /// Returns the direct parent OIDs of `commit` (`[p1]` or `[p1, p2]`).
    pub fn commit_parents(&self, commit: &GitOid) -> Result<Vec<GitOid>, GitError> {
        let out = self.run_local(&["rev-list", "--parents", "-n", "1", &commit.to_hex()])?;
        let line = String::from_utf8_lossy(&out);
        let mut parts = line.split_whitespace();
        let _self_oid = parts.next();
        parts
            .map(|p| GitOid::from_hex(p).map_err(|e| GitError::Parse(e.to_string())))
            .collect()
    }

    /// Returns `git rev-list --first-parent --reverse base..tip` (`S_1..=S_k`).
    pub fn first_parent_chain(&self, base: &GitOid, tip: &GitOid) -> Result<Vec<GitOid>, GitError> {
        if base == tip {
            return Ok(Vec::new());
        }
        let range = format!("{base}..{tip}");
        let out = self.run_local(&["rev-list", "--first-parent", "--reverse", &range])?;
        String::from_utf8_lossy(&out)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| GitOid::from_hex(l.trim()).map_err(|e| GitError::Parse(e.to_string())))
            .collect()
    }

    /// Returns all commits reachable from `tip` excluding `base` (`git rev-list --reverse base..tip`).
    pub fn rev_list_range(&self, base: &GitOid, tip: &GitOid) -> Result<Vec<GitOid>, GitError> {
        if base == tip {
            return Ok(Vec::new());
        }
        let range = format!("{base}..{tip}");
        let out = self.run_local(&["rev-list", "--reverse", &range])?;
        String::from_utf8_lossy(&out)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| GitOid::from_hex(l.trim()).map_err(|e| GitError::Parse(e.to_string())))
            .collect()
    }

    /// Reads the raw commit message body (`%B`) of `commit`.
    pub fn commit_message(&self, commit: &GitOid) -> Result<String, GitError> {
        let out = self.run_local(&["log", "-1", "--pretty=%B", &commit.to_hex()])?;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// Runs `git merge-tree --write-tree --merge-base=<mb> <b1> <b2>` purely in
    /// the bare object store (immune to `.gitattributes` `merge.<name>.driver`
    /// execution) and returns `Some(tree_oid)` on a clean merge or `None` on
    /// merge conflict (`exit 1`).
    pub fn merge_tree_clean(
        &self,
        merge_base: &GitOid,
        branch1: &GitOid,
        branch2: &GitOid,
    ) -> Result<Option<GitOid>, GitError> {
        let out = Self::base_command(&self.git_dir)
            .args([
                "merge-tree",
                "--write-tree",
                &format!("--merge-base={merge_base}"),
                &branch1.to_hex(),
                &branch2.to_hex(),
            ])
            .output()
            .map_err(|e| GitError::Command {
                cmd: "git merge-tree --write-tree".to_owned(),
                reason: e.to_string(),
            })?;
        match out.status.code() {
            Some(0) => {
                let first_line = String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_owned();
                let oid =
                    GitOid::from_hex(&first_line).map_err(|e| GitError::Parse(e.to_string()))?;
                Ok(Some(oid))
            }
            Some(1) => Ok(None),
            _ => Err(GitError::Command {
                cmd: "git merge-tree --write-tree".to_owned(),
                reason: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone)]
struct IndexedGitEntry {
    kind: EntryKind,
    blob_oid: GitOid,
    executable: bool,
}

/// Read-only `SourceTree` backed by an immutable commit/tree in a
/// `HardenedBareGit` store (`0` worktree checkout).
#[derive(Debug, Clone)]
pub struct BareGitTree {
    git: HardenedBareGit,
    tree_oid: GitOid,
    entries: BTreeMap<RepoRelPath, IndexedGitEntry>,
    dirs: BTreeSet<RepoRelPath>,
    symlink_targets: BTreeMap<RepoRelPath, String>,
}

impl BareGitTree {
    /// Indexes `commit_or_tree` from `git` via `git ls-tree -r -t -z`.
    pub fn from_commit(git: HardenedBareGit, commit: &GitOid) -> Result<Self, GitError> {
        let tree_oid = git.commit_tree_oid(commit)?;
        Self::from_tree_oid(git, tree_oid)
    }

    /// Indexes an explicit `tree_oid`.
    pub fn from_tree_oid(git: HardenedBareGit, tree_oid: GitOid) -> Result<Self, GitError> {
        let raw = git.run_local(&["ls-tree", "-r", "-t", "-z", &tree_oid.to_hex()])?;
        let mut entries = BTreeMap::new();
        let mut dirs = BTreeSet::new();
        let mut symlink_paths = Vec::new();

        for rec in raw.split(|&b| b == 0) {
            if rec.is_empty() {
                continue;
            }
            let Some(tab_pos) = rec.iter().position(|&b| b == b'\t') else {
                return Err(GitError::Parse("missing tab in git ls-tree".to_owned()));
            };
            let header =
                std::str::from_utf8(&rec[..tab_pos]).map_err(|e| GitError::Parse(e.to_string()))?;
            let path_str = std::str::from_utf8(&rec[tab_pos + 1..])
                .map_err(|e| GitError::Parse(e.to_string()))?;
            let Ok(rel_path) = RepoRelPath::new(path_str) else {
                return Err(GitError::Parse(format!(
                    "unsafe path {path_str:?} in git tree {tree_oid}"
                )));
            };
            let mut hparts = header.split_whitespace();
            let mode = hparts.next().unwrap_or_default();
            let _obj_type = hparts.next().unwrap_or_default();
            let oid_s = hparts.next().unwrap_or_default();
            let obj_oid = GitOid::from_hex(oid_s).map_err(|e| GitError::Parse(e.to_string()))?;

            match mode {
                "040000" => {
                    dirs.insert(rel_path);
                }
                "100644" => {
                    entries.insert(
                        rel_path,
                        IndexedGitEntry {
                            kind: EntryKind::File,
                            blob_oid: obj_oid,
                            executable: false,
                        },
                    );
                }
                "100755" => {
                    entries.insert(
                        rel_path,
                        IndexedGitEntry {
                            kind: EntryKind::File,
                            blob_oid: obj_oid,
                            executable: true,
                        },
                    );
                }
                "120000" => {
                    symlink_paths.push((rel_path.clone(), obj_oid));
                    entries.insert(
                        rel_path,
                        IndexedGitEntry {
                            kind: EntryKind::Symlink,
                            blob_oid: obj_oid,
                            executable: false,
                        },
                    );
                }
                "160000" => {
                    entries.insert(
                        rel_path,
                        IndexedGitEntry {
                            kind: EntryKind::Gitlink,
                            blob_oid: obj_oid,
                            executable: false,
                        },
                    );
                }
                _ => {
                    entries.insert(
                        rel_path,
                        IndexedGitEntry {
                            kind: EntryKind::Special,
                            blob_oid: obj_oid,
                            executable: false,
                        },
                    );
                }
            }
        }

        let mut symlink_targets = BTreeMap::new();
        for (spath, boid) in symlink_paths {
            let bytes = git.run_local(&["cat-file", "blob", &boid.to_hex()])?;
            let target = String::from_utf8(bytes)
                .map_err(|e| GitError::Parse(format!("non-UTF-8 symlink `{spath}`: {e}")))?;
            symlink_targets.insert(spath, target);
        }

        Ok(Self {
            git,
            tree_oid,
            entries,
            dirs,
            symlink_targets,
        })
    }

    /// Root Git tree OID of this snapshot.
    pub const fn tree_oid(&self) -> GitOid {
        self.tree_oid
    }

    /// Returns the raw Git blob OID of `path` (`None` if absent or directory).
    pub fn blob_oid(&self, path: &RepoRelPath) -> Option<GitOid> {
        self.entries.get(path).map(|e| e.blob_oid)
    }
}

impl SourceTree for BareGitTree {
    fn entry(&self, path: &RepoRelPath) -> Result<Option<TreeEntry>, TreeError> {
        let Some(ie) = self.entries.get(path) else {
            return Ok(None);
        };
        Ok(Some(match ie.kind {
            EntryKind::File => TreeEntry::Regular {
                executable: ie.executable,
            },
            EntryKind::Symlink => TreeEntry::Symlink {
                target: self.symlink_targets.get(path).cloned().unwrap_or_default(),
            },
            EntryKind::Gitlink => TreeEntry::Gitlink { oid: ie.blob_oid },
            EntryKind::Special | EntryKind::Dir => TreeEntry::Special,
        }))
    }

    fn list_dir(&self, dir: Option<&RepoRelPath>) -> Result<Vec<(String, EntryKind)>, TreeError> {
        let mut out: BTreeMap<String, EntryKind> = BTreeMap::new();
        let prefix = dir.map(|d| format!("{}/", d.as_str()));

        let mut add_rel = |rel: &str, k: EntryKind| {
            if let Some((seg, _)) = rel.split_once('/') {
                out.entry(seg.to_owned()).or_insert(EntryKind::Dir);
            } else if !rel.is_empty() {
                out.insert(rel.to_owned(), k);
            }
        };

        for (p, ie) in &self.entries {
            match &prefix {
                None => add_rel(p.as_str(), ie.kind),
                Some(pre) => {
                    if let Some(rel) = p.as_str().strip_prefix(pre) {
                        add_rel(rel, ie.kind);
                    }
                }
            }
        }
        for d in &self.dirs {
            match &prefix {
                None => add_rel(d.as_str(), EntryKind::Dir),
                Some(pre) => {
                    if let Some(rel) = d.as_str().strip_prefix(pre) {
                        add_rel(rel, EntryKind::Dir);
                    }
                }
            }
        }
        Ok(out.into_iter().collect())
    }

    fn read_blob(&self, path: &RepoRelPath) -> Result<Vec<u8>, TreeError> {
        let Some(ie) = self.entries.get(path) else {
            return Err(TreeError::MissingPath(path.clone()));
        };
        if ie.kind != EntryKind::File {
            return Err(TreeError::MissingPath(path.clone()));
        }
        self.git
            .run_local(&["cat-file", "blob", &ie.blob_oid.to_hex()])
            .map_err(|e| TreeError::Io(e.to_string()))
    }

    fn all_paths(&self) -> Result<Vec<RepoRelPath>, TreeError> {
        Ok(self.entries.keys().cloned().collect())
    }
}

/// Bare-Git commit-slice replayer (`MERGE`, `SQUASH`, `REBASE`) for
/// `evaluate_merge_group_tcb`.
pub struct BareGitSliceReplayer<'a> {
    git: &'a HardenedBareGit,
    merge_method: MergeMethod,
    chain_commits: &'a [GitOid],
    chain_tree_oids: &'a [GitOid],
}

impl<'a> BareGitSliceReplayer<'a> {
    /// Creates a replayer over `S_0..=S_k` (`chain_commits` and `chain_tree_oids`).
    pub fn new(
        git: &'a HardenedBareGit,
        merge_method: MergeMethod,
        chain_commits: &'a [GitOid],
        chain_tree_oids: &'a [GitOid],
    ) -> Self {
        Self {
            git,
            merge_method,
            chain_commits,
            chain_tree_oids,
        }
    }
}

impl CommitSliceReplayer for BareGitSliceReplayer<'_> {
    fn try_replay_entry(
        &self,
        c_cur: usize,
        entry: &MergeQueueEntry,
    ) -> Result<Option<usize>, String> {
        if c_cur + 1 >= self.chain_commits.len() {
            return Ok(None);
        }
        let base_commit = &self.chain_commits[c_cur];
        let pr_head = &entry.head_oid;
        let mb = self
            .git
            .merge_base_with_deepening(base_commit, pr_head)
            .map_err(|e| e.to_string())?;

        match self.merge_method {
            MergeMethod::Merge | MergeMethod::Squash => {
                // Both `MERGE` and `SQUASH` produce 1 commit whose root tree
                // equals `merge-tree(mb, S_{c_cur}, PR.head_oid)`.
                let Some(replayed_tree) = self
                    .git
                    .merge_tree_clean(&mb, base_commit, pr_head)
                    .map_err(|e| e.to_string())?
                else {
                    return Ok(None);
                };
                if replayed_tree == self.chain_tree_oids[c_cur + 1] {
                    Ok(Some(1))
                } else {
                    Ok(None)
                }
            }
            MergeMethod::Rebase => {
                // `REBASE` replays `n >= 1` linear commits `mb..PR.head_oid`
                // one by one with `--merge-base=c^1`, failing closed on inner
                // merge commits or conflicts and matching every intermediate
                // and final tree against `S_{c_cur+1}..S_{c_cur+n}`.
                let linear = self
                    .git
                    .first_parent_chain(&mb, pr_head)
                    .map_err(|e| e.to_string())?;
                let n = linear.len();
                if n == 0 || c_cur + n >= self.chain_tree_oids.len() {
                    return Ok(None);
                }
                // Replay commit 1 onto `S_{c_cur}` (`merge-base = c_1^1`), then
                // each subsequent `c_m` onto the previous replayed tree!
                // Note: `git merge-tree --write-tree --merge-base=<parent> <prev_tree> <commit>`
                // works directly on tree OIDs as well as commit OIDs in Git 2.40+!
                let mut prev_ref_oid = *base_commit;
                for (step_idx, pr_commit) in linear.iter().enumerate() {
                    let parents = self
                        .git
                        .commit_parents(pr_commit)
                        .map_err(|e| e.to_string())?;
                    if parents.len() != 1 {
                        // Inner merge commit inside a `REBASE` PR fails closed.
                        return Err(format!(
                            "REBASE PR #{} contains non-linear merge commit `{pr_commit}`",
                            entry.pr_number
                        ));
                    }
                    let parent_oid = parents[0];
                    let Some(step_tree) = self
                        .git
                        .merge_tree_clean(&parent_oid, &prev_ref_oid, pr_commit)
                        .map_err(|e| e.to_string())?
                    else {
                        return Ok(None);
                    };
                    if step_tree != self.chain_tree_oids[c_cur + 1 + step_idx] {
                        return Ok(None);
                    }
                    // Advance onto the verified `S_{c_cur + 1 + step_idx}` commit
                    // whose tree equals `step_tree`.
                    prev_ref_oid = self.chain_commits[c_cur + 1 + step_idx];
                }
                Ok(Some(n))
            }
        }
    }
}

/// Symmetric live GitHub API `/codeowners/errors` helper (`§4.2`) shared across
/// `plan`, `publish`, and `gate`:
/// - Queries `H_default` iff `live_cfg` uses `CallerMode::RepoRuleset`.
/// - Queries `event_sha` iff `target_cfg` uses `CallerMode::RepoRuleset`
///   (reusing `live_errors` without a duplicate API call when both are
///   `RepoRuleset` and `.github/CODEOWNERS` has the identical Git blob OID).
pub fn fetch_codeowners_error_pair(
    api: &dyn GitHubApi,
    live_onboarded: Option<(&ChecksConfig, &BareGitTree, &GitOid)>,
    target_cfg: &ChecksConfig,
    target_tree: &BareGitTree,
    event_sha: &GitOid,
) -> Result<(Vec<String>, Vec<String>), String> {
    let co_path = RepoRelPath::new(".github/CODEOWNERS").expect("static");
    let target_is_repo_rs = matches!(target_cfg.tcb.caller, CallerMode::RepoRuleset { .. });

    let (live_is_repo_rs, live_co_blob, live_errors) = match live_onboarded {
        Some((live_cfg, live_tree, h_default_sha))
            if matches!(live_cfg.tcb.caller, CallerMode::RepoRuleset { .. }) =>
        {
            let errs = api
                .get_codeowners_errors(h_default_sha)
                .map_err(|e| format!("GET codeowners/errors?ref={h_default_sha}: {e}"))?;
            (true, live_tree.blob_oid(&co_path), errs)
        }
        _ => (false, None, Vec::new()),
    };

    let target_errors = if target_is_repo_rs {
        if live_is_repo_rs && live_co_blob == target_tree.blob_oid(&co_path) {
            live_errors.clone()
        } else {
            api.get_codeowners_errors(event_sha)
                .map_err(|e| format!("GET codeowners/errors?ref={event_sha}: {e}"))?
        }
    } else {
        Vec::new()
    };

    Ok((live_errors, target_errors))
}

/// Developer worktree `SourceTree` (`lstat` semantics, zero `.git` dependency,
/// skipping `.git` and Cargo `target` build output directories).
#[derive(Debug, Clone)]
pub struct LocalWorktree {
    root: PathBuf,
}

impl LocalWorktree {
    /// Opens a local repository checkout directory.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, TreeError> {
        let r = root.into();
        let meta = fs::symlink_metadata(&r).map_err(|e| TreeError::Io(e.to_string()))?;
        if !meta.file_type().is_dir() {
            return Err(TreeError::Io(format!(
                "worktree root `{}` is not a real directory",
                r.display()
            )));
        }
        Ok(Self { root: r })
    }

    /// Root filesystem path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn host_path(&self, rel: Option<&RepoRelPath>) -> PathBuf {
        match rel {
            None => self.root.clone(),
            Some(p) => self.root.join(p.as_str()),
        }
    }

    fn should_skip_dir_entry(parent: Option<&RepoRelPath>, name: &str, kind: EntryKind) -> bool {
        if name == ".git" {
            return true;
        }
        // Skip Cargo `target/` build directories (`root/target` or `<ws>/target`
        // when sibling `Cargo.toml` exists).
        if name == "target" && kind == EntryKind::Dir && parent.is_none() {
            return true;
        }
        false
    }

    fn classify_meta(meta: &fs::Metadata) -> EntryKind {
        let ft = meta.file_type();
        if ft.is_symlink() {
            EntryKind::Symlink
        } else if ft.is_dir() {
            EntryKind::Dir
        } else if ft.is_file() {
            EntryKind::File
        } else {
            EntryKind::Special
        }
    }
}

impl SourceTree for LocalWorktree {
    fn entry(&self, path: &RepoRelPath) -> Result<Option<TreeEntry>, TreeError> {
        let hp = self.host_path(Some(path));
        let meta = match fs::symlink_metadata(&hp) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(TreeError::Io(format!("{}: {e}", hp.display()))),
        };
        match Self::classify_meta(&meta) {
            EntryKind::Dir => Ok(None),
            EntryKind::File => {
                let executable = (meta.permissions().mode() & 0o100) != 0;
                Ok(Some(TreeEntry::Regular { executable }))
            }
            EntryKind::Symlink => {
                let target_os = fs::read_link(&hp)
                    .map_err(|e| TreeError::Io(format!("read_link {}: {e}", hp.display())))?;
                let target = target_os
                    .to_str()
                    .ok_or_else(|| {
                        TreeError::Io(format!("non-UTF-8 symlink target at {}", hp.display()))
                    })?
                    .to_owned();
                Ok(Some(TreeEntry::Symlink { target }))
            }
            EntryKind::Gitlink | EntryKind::Special => Ok(Some(TreeEntry::Special)),
        }
    }

    fn list_dir(&self, dir: Option<&RepoRelPath>) -> Result<Vec<(String, EntryKind)>, TreeError> {
        let hp = self.host_path(dir);
        let rd = match fs::read_dir(&hp) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(TreeError::Io(format!("{}: {e}", hp.display()))),
        };
        let has_sibling_cargo_toml = hp.join("Cargo.toml").is_file();
        let mut out = BTreeMap::new();
        for ent_res in rd {
            let ent = ent_res.map_err(|e| TreeError::Io(e.to_string()))?;
            let Some(name) = ent.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let meta = fs::symlink_metadata(ent.path())
                .map_err(|e| TreeError::Io(format!("{}: {e}", ent.path().display())))?;
            let kind = Self::classify_meta(&meta);
            if Self::should_skip_dir_entry(dir, &name, kind)
                || (name == "target" && kind == EntryKind::Dir && has_sibling_cargo_toml)
            {
                continue;
            }
            let _ = meta.ino();
            out.insert(name, kind);
        }
        Ok(out.into_iter().collect())
    }

    fn read_blob(&self, path: &RepoRelPath) -> Result<Vec<u8>, TreeError> {
        let hp = self.host_path(Some(path));
        let meta = fs::symlink_metadata(&hp)
            .map_err(|e| TreeError::Io(format!("{}: {e}", hp.display())))?;
        if !meta.file_type().is_file() {
            return Err(TreeError::MissingPath(path.clone()));
        }
        fs::read(&hp).map_err(|e| TreeError::Io(format!("{}: {e}", hp.display())))
    }

    fn all_paths(&self) -> Result<Vec<RepoRelPath>, TreeError> {
        let mut out = Vec::new();
        fn walk_dir(
            wt: &LocalWorktree,
            cur: Option<RepoRelPath>,
            out: &mut Vec<RepoRelPath>,
        ) -> Result<(), TreeError> {
            for (name, kind) in wt.list_dir(cur.as_ref())? {
                let child = match &cur {
                    None => RepoRelPath::new(&name)?,
                    Some(c) => c.join_segment(&name)?,
                };
                if kind == EntryKind::Dir {
                    walk_dir(wt, Some(child), out)?;
                } else {
                    out.push(child);
                }
            }
            Ok(())
        }
        walk_dir(self, None, &mut out)?;
        out.sort();
        Ok(out)
    }
}
