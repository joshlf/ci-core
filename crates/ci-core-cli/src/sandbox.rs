//! Hermetic Linux sandboxes (`Container`, `NestedBwrap`, and `run-local`-only
//! `--native`), `O_NOFOLLOW` output capture, multi-hop confined `.tar.zst`
//! cache hydration/packing (`internal_link_count == st_nlink`), and isolated-
//! `cwd` `cargo_locked` fetching (`Obligations O4, O6, O9`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ci_core_model::cargo_static::CargoLockedFetchPlan;
use ci_core_model::config::DeclaredOutputSpec;
use ci_core_model::tree::{
    ConfinedEntry, SourceTree, ValidatedSourceClosure, validate_confined_dir,
};
use ci_core_model::types::{
    AbsUnixPath, OutputDigest, OutputName, PinId, PinKey, Platform, RegistryIndexUrl, RepoRelPath,
    Sha256Digest, pin_env_var_name,
};
use rustix::fs::{
    CWD, FileType, Mode, OFlags, ResolveFlags, fstat, mkdirat, openat, openat2, symlinkat,
};
use rustix::process::{getgid, getuid};
use rustix::system::uname;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::ghcr::VerifiedOciLayout;

/// Errors returned by sandbox setup, cache I/O, `cargo_locked` fetching, or
/// output capture.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// Host architecture (`uname -m`) did not match configured `Platform`.
    #[error("runner architecture `{uname}` does not match image platform `{platform}`")]
    ArchMismatch {
        /// Observed `uname -m`.
        uname: String,
        /// Configured OCI platform.
        platform: Platform,
    },
    /// Sandbox or helper command failed to launch or returned unexpected error.
    #[error("sandbox execution error: {0}")]
    Exec(String),
    /// Declared output failed `O_NOFOLLOW`, `S_ISREG`, `nlink == 1`, or size
    /// checks.
    #[error("output capture rejected `{name}`: {reason}")]
    OutputRejected {
        /// Declared output filename.
        name: OutputName,
        /// Rejection reason.
        reason: String,
    },
    /// Cache archive/directory failed confinement, hardlink, or `max_bytes`
    /// checks.
    #[error("cache slot archive rejected: {0}")]
    CacheRejected(String),
    /// Pre-sandbox `cargo fetch --locked` failed.
    #[error("isolated cargo_locked fetch failed: {0}")]
    CargoFetch(String),
    /// Filesystem I/O failure.
    #[error("filesystem error: {0}")]
    Io(String),
}

/// Returns `(uid, gid)` of the current unprivileged runner user.
pub fn host_uid_gid() -> (u32, u32) {
    (getuid().as_raw(), getgid().as_raw())
}

/// Queries kernel `utsname.machine` directly via `rustix::system::uname` and
/// asserts compatibility with `platform` (`0` subprocess fork).
pub fn verify_host_platform(platform: Platform) -> Result<(), SandboxError> {
    let arch = uname().machine().to_string_lossy().trim().to_owned();
    if !platform.matches_uname_arch(&arch) {
        return Err(SandboxError::ArchMismatch {
            uname: arch,
            platform,
        });
    }
    Ok(())
}

/// Returns `true` if `key` is a reserved host/runner/loader variable that must
/// be stripped before entering any sandbox.
pub fn is_stripped_env_key(key: &str) -> bool {
    matches!(key, "HOME" | "TMPDIR" | "LD_PRELOAD" | "BASH_ENV")
        || key.starts_with("GITHUB_")
        || key.starts_with("ACTIONS_")
        || key.starts_with("RUNNER_")
}

/// Parses `["K=V", ...]` from a verified OCI image `Config.Env`, stripping
/// reserved runner and dynamic-linker variables.
pub fn filter_oci_config_env(raw_oci_env: &[String]) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for entry in raw_oci_env {
        if let Some((k, v)) = entry.split_once('=')
            && !k.is_empty()
            && !is_stripped_env_key(k)
        {
            env.insert(k.to_owned(), v.to_owned());
        }
    }
    env
}

/// Builds the complete deterministic environment map injected into a check
/// sandbox (`OCI Config.Env` overridden by `HOME=/scratch`, `TMPDIR=/tmp`,
/// check `env`, and `PIN_<NORM_PIN>__<NORM_KEY>`).
pub fn build_sandbox_env(
    oci_config_env: &[String],
    check_env: &BTreeMap<String, String>,
    pins: &BTreeMap<PinId, BTreeMap<PinKey, String>>,
    home_dir: &str,
    tmp_dir: &str,
) -> BTreeMap<String, String> {
    let mut merged = filter_oci_config_env(oci_config_env);
    merged.insert("HOME".to_owned(), home_dir.to_owned());
    merged.insert("TMPDIR".to_owned(), tmp_dir.to_owned());
    for (k, v) in check_env {
        if !is_stripped_env_key(k) {
            merged.insert(k.clone(), v.clone());
        }
    }
    for (pid, pmap) in pins {
        for (pkey, pval) in pmap {
            merged.insert(pin_env_var_name(pid, pkey), pval.clone());
        }
    }
    merged
}

/// Opens or creates relative directory `rel_segments` beneath `base_dir`
/// using atomic `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` when the
/// directory already exists, falling back to segment-by-segment `O_DIRECTORY |
/// O_NOFOLLOW` + `mkdirat` creation.
pub fn open_or_create_dir_nofollow(
    base_dir: &Path,
    rel_segments: &[&str],
) -> Result<rustix::fd::OwnedFd, SandboxError> {
    let mut cur_fd = openat(
        CWD,
        base_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|e| SandboxError::Io(format!("openat {}: {e}", base_dir.display())))?;

    if rel_segments.is_empty() {
        return Ok(cur_fd);
    }
    for &seg in rel_segments {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(SandboxError::Io(format!(
                "invalid relative segment {seg:?} in O_NOFOLLOW walk"
            )));
        }
    }

    let joined = rel_segments.join("/");
    match openat2(
        &cur_fd,
        joined.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    ) {
        Ok(fd) => return Ok(fd),
        Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOSYS | rustix::io::Errno::PERM) => {}
        Err(e) => {
            return Err(SandboxError::Io(format!(
                "openat2 `{joined}` beneath {}: {e}",
                base_dir.display()
            )));
        }
    }

    for &seg in rel_segments {
        match openat(
            &cur_fd,
            seg,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(next_fd) => {
                cur_fd = next_fd;
            }
            Err(rustix::io::Errno::NOENT) => {
                mkdirat(&cur_fd, seg, Mode::from_raw_mode(0o755))
                    .map_err(|e| SandboxError::Io(format!("mkdirat `{seg}`: {e}")))?;
                cur_fd = openat(
                    &cur_fd,
                    seg,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|e| SandboxError::Io(format!("openat `{seg}` after mkdirat: {e}")))?;
            }
            Err(e) => {
                return Err(SandboxError::Io(format!(
                    "openat `{seg}` with O_NOFOLLOW failed: {e}"
                )));
            }
        }
    }
    Ok(cur_fd)
}

/// Materializes a `ValidatedSourceClosure` into a fresh `work_dir` and
/// pre-creates empty `writable_dirs` mountpoints strictly via fd-relative
/// `openat(O_NOFOLLOW)` and `symlinkat` (`0` path-based TOCTOU, `0` `.git`
/// exposure).
pub fn materialize_work_closure(
    tree: &dyn SourceTree,
    closure: &ValidatedSourceClosure,
    work_dir: &Path,
    writable_dirs: &[RepoRelPath],
    workdir: Option<&RepoRelPath>,
) -> Result<(), SandboxError> {
    if work_dir.exists() {
        fs::remove_dir_all(work_dir).map_err(|e| SandboxError::Io(e.to_string()))?;
    }
    fs::create_dir_all(work_dir).map_err(|e| SandboxError::Io(e.to_string()))?;

    for (rel_path, mentry) in closure.entries() {
        let segs: Vec<&str> = rel_path.as_str().split('/').collect();
        let (parent_segs, leaf) = segs.split_at(segs.len() - 1);
        let leaf_name = leaf[0];
        let parent_fd = open_or_create_dir_nofollow(work_dir, parent_segs)?;
        match mentry {
            ci_core_model::digest::MerkleEntry::Regular { executable, .. } => {
                let bytes = tree
                    .read_blob(rel_path)
                    .map_err(|e| SandboxError::Io(e.to_string()))?;
                let mode = if *executable { 0o755 } else { 0o644 };
                let file_fd = openat(
                    &parent_fd,
                    leaf_name,
                    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW,
                    Mode::from_raw_mode(mode),
                )
                .map_err(|e| SandboxError::Io(format!("openat create `{rel_path}`: {e}")))?;
                let mut f = File::from(file_fd);
                f.write_all(&bytes)
                    .map_err(|e| SandboxError::Io(e.to_string()))?;
                f.set_permissions(fs::Permissions::from_mode(mode))
                    .map_err(|e| SandboxError::Io(e.to_string()))?;
            }
            ci_core_model::digest::MerkleEntry::Symlink { target } => {
                symlinkat(target.as_str(), &parent_fd, leaf_name)
                    .map_err(|e| SandboxError::Io(format!("symlinkat `{rel_path}`: {e}")))?;
            }
        }
    }

    if let Some(wd) = workdir {
        let segs: Vec<&str> = wd.as_str().split('/').collect();
        let _ = open_or_create_dir_nofollow(work_dir, &segs)?;
    }

    for wdir in writable_dirs {
        let segs: Vec<&str> = wdir.as_str().split('/').collect();
        let _ = open_or_create_dir_nofollow(work_dir, &segs)?;
    }

    Ok(())
}

/// Captures declared outputs from `outputs_dir` using `O_NOFOLLOW`, asserting
/// `S_ISREG`, `st_nlink == 1`, and `size <= spec.max_bytes` (`§5.2`, blocking
/// `/outputs/lcov.info -> /proc/self/environ` symlink and hardlink attacks).
pub fn capture_declared_outputs(
    outputs_dir: &Path,
    declared: &BTreeMap<OutputName, DeclaredOutputSpec>,
    stage_blobs_dir: Option<&Path>,
) -> Result<BTreeMap<OutputName, OutputDigest>, SandboxError> {
    if declared.is_empty() {
        return Ok(BTreeMap::new());
    }
    let dir_fd = openat(
        CWD,
        outputs_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|e| SandboxError::Io(format!("openat outputs_dir: {e}")))?;

    if let Some(sdir) = stage_blobs_dir {
        fs::create_dir_all(sdir).map_err(|e| SandboxError::Io(e.to_string()))?;
    }

    let mut captured = BTreeMap::new();
    for (name, spec) in declared {
        let fd = openat(
            &dir_fd,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|e| SandboxError::OutputRejected {
            name: name.clone(),
            reason: format!("openat(O_NOFOLLOW) failed: {e}"),
        })?;

        let st = fstat(&fd).map_err(|e| SandboxError::OutputRejected {
            name: name.clone(),
            reason: format!("fstat failed: {e}"),
        })?;
        let ft = FileType::from_raw_mode(st.st_mode);
        if ft != FileType::RegularFile {
            return Err(SandboxError::OutputRejected {
                name: name.clone(),
                reason: format!("expected regular file, found {ft:?}"),
            });
        }
        if st.st_nlink as u64 != 1 {
            return Err(SandboxError::OutputRejected {
                name: name.clone(),
                reason: format!("expected st_nlink == 1, found {}", st.st_nlink),
            });
        }
        let fstat_size = st.st_size.max(0) as u64;
        if fstat_size > spec.max_bytes {
            return Err(SandboxError::OutputRejected {
                name: name.clone(),
                reason: format!("size {fstat_size} exceeds max_bytes {}", spec.max_bytes),
            });
        }

        let mut reader = File::from(fd);
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        let mut buf = [0u8; 65_536];
        let mut stage_tmp = match stage_blobs_dir {
            Some(sdir) => Some(
                File::create(sdir.join(format!(".tmp-out-{}", name.as_str())))
                    .map_err(|e| SandboxError::Io(e.to_string()))?,
            ),
            None => None,
        };

        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| SandboxError::OutputRejected {
                    name: name.clone(),
                    reason: format!("read failed: {e}"),
                })?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > spec.max_bytes {
                return Err(SandboxError::OutputRejected {
                    name: name.clone(),
                    reason: format!(
                        "streamed bytes {total} exceeded max_bytes {}",
                        spec.max_bytes
                    ),
                });
            }
            hasher.update(&buf[..n]);
            if let Some(ref mut w) = stage_tmp {
                w.write_all(&buf[..n])
                    .map_err(|e| SandboxError::Io(e.to_string()))?;
            }
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hasher.finalize());
        let sha256 = Sha256Digest::from_bytes(arr);

        if let (Some(sdir), Some(w)) = (stage_blobs_dir, stage_tmp) {
            w.sync_all().map_err(|e| SandboxError::Io(e.to_string()))?;
            drop(w);
            fs::rename(
                sdir.join(format!(".tmp-out-{}", name.as_str())),
                sdir.join(sha256.to_hex()),
            )
            .map_err(|e| SandboxError::Io(e.to_string()))?;
        }

        captured.insert(
            name.clone(),
            OutputDigest {
                sha256,
                size_bytes: total,
            },
        );
    }

    Ok(captured)
}

/// Validates and extracts a `.tar.zst` cache archive into `dest_cache_dir`
/// opening every parent component and file with `O_NOFOLLOW` (`§5.2`).
pub fn hydrate_cache_archive(
    archive_path: &Path,
    dest_cache_dir: &Path,
    max_unpacked_bytes: u64,
) -> Result<(), SandboxError> {
    // Pass 1: Pre-validate all TAR headers, symlink chains, and internal
    // hardlinks before touching `dest_cache_dir`.
    {
        let f = File::open(archive_path).map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
        let dec = zstd::Decoder::new(f).map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
        let mut ar = tar::Archive::new(dec);
        let mut entry_map: BTreeMap<RepoRelPath, ConfinedEntry> = BTreeMap::new();
        let mut regular_seen: BTreeSet<RepoRelPath> = BTreeSet::new();
        let mut unpacked_sum = 0u64;

        let entries = ar
            .entries()
            .map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
        for ent_res in entries {
            let ent = ent_res.map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
            let header = ent.header();
            let raw_path = ent
                .path()
                .map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
            let path_s = raw_path
                .to_str()
                .ok_or_else(|| SandboxError::CacheRejected("non-UTF-8 tar path".to_owned()))?
                .trim_start_matches("./")
                .trim_end_matches('/');
            if path_s.is_empty() {
                continue;
            }
            let rel = RepoRelPath::new(path_s)
                .map_err(|e| SandboxError::CacheRejected(format!("invalid tar path: {e}")))?;
            let mode = header.mode().unwrap_or(0o644);
            if (mode & 0o6000) != 0 {
                return Err(SandboxError::CacheRejected(format!(
                    "setuid/setgid mode {mode:#o} forbidden at `{rel}`"
                )));
            }
            let etype = header.entry_type();
            if etype.is_file() {
                let sz = header.size().unwrap_or(0);
                unpacked_sum = unpacked_sum.saturating_add(sz);
                if unpacked_sum > max_unpacked_bytes.saturating_mul(4) {
                    return Err(SandboxError::CacheRejected(
                        "unpacked cache exceeded decompression ratio bound".to_owned(),
                    ));
                }
                regular_seen.insert(rel.clone());
                entry_map.insert(rel, ConfinedEntry::Regular);
            } else if etype.is_dir() {
                entry_map.insert(rel, ConfinedEntry::Dir);
            } else if etype.is_symlink() {
                let link_name = ent
                    .link_name()
                    .map_err(|e| SandboxError::CacheRejected(e.to_string()))?
                    .ok_or_else(|| {
                        SandboxError::CacheRejected(format!("symlink `{rel}` missing target"))
                    })?;
                let target = link_name
                    .to_str()
                    .ok_or_else(|| SandboxError::CacheRejected("non-UTF-8 link target".to_owned()))?
                    .to_owned();
                entry_map.insert(rel, ConfinedEntry::Symlink { target });
            } else if etype.is_hard_link() {
                let link_name = ent
                    .link_name()
                    .map_err(|e| SandboxError::CacheRejected(e.to_string()))?
                    .ok_or_else(|| {
                        SandboxError::CacheRejected(format!("hardlink `{rel}` missing target"))
                    })?;
                let target_s = link_name
                    .to_str()
                    .ok_or_else(|| SandboxError::CacheRejected("non-UTF-8 hardlink".to_owned()))?
                    .trim_start_matches("./");
                let target_rel = RepoRelPath::new(target_s)
                    .map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
                if !regular_seen.contains(&target_rel) {
                    return Err(SandboxError::CacheRejected(format!(
                        "hardlink `{rel}` -> `{target_rel}` does not reference an earlier regular file"
                    )));
                }
                entry_map.insert(rel, ConfinedEntry::Regular);
            } else {
                return Err(SandboxError::CacheRejected(format!(
                    "unsupported tar entry type {etype:?} at `{rel}`"
                )));
            }
        }
        validate_confined_dir(&entry_map)
            .map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
    }

    // Pass 2: Extract with `O_NOFOLLOW` on every parent component and file.
    if dest_cache_dir.exists() {
        fs::remove_dir_all(dest_cache_dir).map_err(|e| SandboxError::Io(e.to_string()))?;
    }
    fs::create_dir_all(dest_cache_dir).map_err(|e| SandboxError::Io(e.to_string()))?;

    let f = File::open(archive_path).map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
    let dec = zstd::Decoder::new(f).map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
    let mut ar = tar::Archive::new(dec);
    for ent_res in ar
        .entries()
        .map_err(|e| SandboxError::CacheRejected(e.to_string()))?
    {
        let mut ent = ent_res.map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
        let raw_path = ent
            .path()
            .map_err(|e| SandboxError::CacheRejected(e.to_string()))?
            .into_owned();
        let path_s = raw_path
            .to_str()
            .unwrap_or_default()
            .trim_start_matches("./")
            .trim_end_matches('/');
        if path_s.is_empty() {
            continue;
        }
        let rel =
            RepoRelPath::new(path_s).map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
        let segs: Vec<&str> = rel.as_str().split('/').collect();
        let etype = ent.header().entry_type();
        let mode = ent.header().mode().unwrap_or(0o644) & 0o777;

        if etype.is_dir() {
            let _ = open_or_create_dir_nofollow(dest_cache_dir, &segs)?;
        } else {
            let (parent_segs, leaf_slice) = segs.split_at(segs.len() - 1);
            let parent_fd = open_or_create_dir_nofollow(dest_cache_dir, parent_segs)?;
            let leaf = leaf_slice[0];
            if etype.is_file() {
                let file_mode = if (mode & 0o100) != 0 { 0o755 } else { 0o644 };
                let out_fd = openat(
                    &parent_fd,
                    leaf,
                    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW,
                    Mode::from_raw_mode(file_mode),
                )
                .map_err(|e| SandboxError::CacheRejected(format!("openat `{rel}`: {e}")))?;
                let mut out_file = File::from(out_fd);
                std::io::copy(&mut ent, &mut out_file)
                    .map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
            } else if etype.is_symlink() {
                let target = ent
                    .link_name()
                    .map_err(|e| SandboxError::CacheRejected(e.to_string()))?
                    .expect("validated in Pass 1")
                    .to_str()
                    .expect("validated in Pass 1")
                    .to_owned();
                rustix::fs::symlinkat(target.as_str(), &parent_fd, leaf)
                    .map_err(|e| SandboxError::CacheRejected(format!("symlinkat `{rel}`: {e}")))?;
            } else if etype.is_hard_link() {
                let target_s = ent
                    .link_name()
                    .map_err(|e| SandboxError::CacheRejected(e.to_string()))?
                    .expect("validated in Pass 1")
                    .to_str()
                    .expect("validated in Pass 1")
                    .trim_start_matches("./")
                    .to_owned();
                let target_rel = RepoRelPath::new(&target_s)
                    .map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
                let tsegs: Vec<&str> = target_rel.as_str().split('/').collect();
                let (t_parents, t_leaf_slice) = tsegs.split_at(tsegs.len() - 1);
                let target_parent_fd = open_or_create_dir_nofollow(dest_cache_dir, t_parents)?;
                rustix::fs::linkat(
                    &target_parent_fd,
                    t_leaf_slice[0],
                    &parent_fd,
                    leaf,
                    rustix::fs::AtFlags::empty(),
                )
                .map_err(|e| SandboxError::CacheRejected(format!("linkat `{rel}`: {e}")))?;
            }
        }
    }

    Ok(())
}

fn is_transient_cargo_lock_file(rel: &RepoRelPath) -> bool {
    let s = rel.as_str();
    s == ".global-cache" || s.starts_with(".package-cache")
}

/// Validates `cache_dir` (`tree::validate_confined_dir`, `O_NOFOLLOW`, and
/// `internal_link_count(st_dev, st_ino) == st_nlink`) and packs a deterministic
/// `.tar.zst` archive (`mtime = 0`, `uid = gid = 0`, sorted POSIX paths).
///
/// Returns `Ok(None)` if `cache_dir` is empty (after skipping Cargo's transient
/// `.package-cache*` and `.global-cache` files on `cargo_locked` slots).
pub fn pack_cache_archive(
    cache_dir: &Path,
    dest_archive_path: &Path,
    max_bytes: u64,
    is_cargo_locked_slot: bool,
) -> Result<Option<(Sha256Digest, u64)>, SandboxError> {
    #[derive(Debug)]
    enum DiscoveredNode {
        Regular {
            dev: u64,
            ino: u64,
            nlink: u64,
            executable: bool,
            size: u64,
        },
        Dir,
        Symlink {
            target: String,
        },
    }

    let mut nodes: BTreeMap<RepoRelPath, DiscoveredNode> = BTreeMap::new();
    let mut entry_map: BTreeMap<RepoRelPath, ConfinedEntry> = BTreeMap::new();
    let mut ino_counts: BTreeMap<(u64, u64), u64> = BTreeMap::new();

    fn walk_nofollow(
        root: &Path,
        cur_rel: Option<RepoRelPath>,
        is_cargo_locked_slot: bool,
        nodes: &mut BTreeMap<RepoRelPath, DiscoveredNode>,
        entry_map: &mut BTreeMap<RepoRelPath, ConfinedEntry>,
        ino_counts: &mut BTreeMap<(u64, u64), u64>,
    ) -> Result<(), SandboxError> {
        let host_cur = match &cur_rel {
            None => root.to_path_buf(),
            Some(r) => root.join(r.as_str()),
        };
        let mut names = Vec::new();
        for ent_res in
            fs::read_dir(&host_cur).map_err(|e| SandboxError::CacheRejected(e.to_string()))?
        {
            let ent = ent_res.map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
            let fname = ent
                .file_name()
                .to_str()
                .ok_or_else(|| SandboxError::CacheRejected("non-UTF-8 cache filename".to_owned()))?
                .to_owned();
            names.push(fname);
        }
        names.sort();

        for name in names {
            let child_rel = match &cur_rel {
                None => RepoRelPath::new(&name)
                    .map_err(|e| SandboxError::CacheRejected(e.to_string()))?,
                Some(p) => p
                    .join_segment(&name)
                    .map_err(|e| SandboxError::CacheRejected(e.to_string()))?,
            };
            if is_cargo_locked_slot && is_transient_cargo_lock_file(&child_rel) {
                continue;
            }
            let child_host = root.join(child_rel.as_str());
            let meta = fs::symlink_metadata(&child_host)
                .map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
            let mode = meta.permissions().mode();
            if (mode & 0o6000) != 0 {
                return Err(SandboxError::CacheRejected(format!(
                    "setuid/setgid bit on `{child_rel}`"
                )));
            }
            let ft = meta.file_type();
            if ft.is_symlink() {
                let target = fs::read_link(&child_host)
                    .map_err(|e| SandboxError::CacheRejected(e.to_string()))?
                    .to_str()
                    .ok_or_else(|| {
                        SandboxError::CacheRejected("non-UTF-8 symlink target".to_owned())
                    })?
                    .to_owned();
                entry_map.insert(
                    child_rel.clone(),
                    ConfinedEntry::Symlink {
                        target: target.clone(),
                    },
                );
                nodes.insert(child_rel, DiscoveredNode::Symlink { target });
            } else if ft.is_dir() {
                entry_map.insert(child_rel.clone(), ConfinedEntry::Dir);
                nodes.insert(child_rel.clone(), DiscoveredNode::Dir);
                walk_nofollow(
                    root,
                    Some(child_rel),
                    is_cargo_locked_slot,
                    nodes,
                    entry_map,
                    ino_counts,
                )?;
            } else if ft.is_file() {
                let dev = meta.dev();
                let ino = meta.ino();
                let nlink = meta.nlink();
                *ino_counts.entry((dev, ino)).or_insert(0) += 1;
                entry_map.insert(child_rel.clone(), ConfinedEntry::Regular);
                nodes.insert(
                    child_rel,
                    DiscoveredNode::Regular {
                        dev,
                        ino,
                        nlink,
                        executable: (mode & 0o100) != 0,
                        size: meta.len(),
                    },
                );
            } else {
                entry_map.insert(child_rel, ConfinedEntry::Special);
            }
        }
        Ok(())
    }

    walk_nofollow(
        cache_dir,
        None,
        is_cargo_locked_slot,
        &mut nodes,
        &mut entry_map,
        &mut ino_counts,
    )?;

    if nodes.is_empty() {
        return Ok(None);
    }

    validate_confined_dir(&entry_map).map_err(|e| SandboxError::CacheRejected(e.to_string()))?;

    // Enforce `internal_link_count(st_dev, st_ino) == st_nlink` across all
    // regular files (allowing internal hardlinks while blocking external links).
    for (rel, node) in &nodes {
        if let DiscoveredNode::Regular {
            dev, ino, nlink, ..
        } = node
        {
            let internal = ino_counts.get(&(*dev, *ino)).copied().unwrap_or(0);
            if internal != *nlink {
                return Err(SandboxError::CacheRejected(format!(
                    "external hardlink detected at `{rel}` (internal_links={internal} != st_nlink={nlink})"
                )));
            }
        }
    }

    if let Some(p) = dest_archive_path.parent() {
        fs::create_dir_all(p).map_err(|e| SandboxError::Io(e.to_string()))?;
    }
    let out_file = File::create(dest_archive_path).map_err(|e| SandboxError::Io(e.to_string()))?;
    let zstd_enc = zstd::Encoder::new(out_file, 3).map_err(|e| SandboxError::Io(e.to_string()))?;
    let mut tar_builder = tar::Builder::new(zstd_enc);
    tar_builder.follow_symlinks(false);

    let mut first_ino_path: BTreeMap<(u64, u64), RepoRelPath> = BTreeMap::new();

    for (rel, node) in &nodes {
        let mut header = tar::Header::new_gnu();
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        let _ = header.set_username("");
        let _ = header.set_groupname("");

        match node {
            DiscoveredNode::Dir => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_mode(0o755);
                header.set_size(0);
                header.set_cksum();
                tar_builder
                    .append_data(&mut header, format!("{}/", rel.as_str()), std::io::empty())
                    .map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
            }
            DiscoveredNode::Symlink { target } => {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_mode(0o777);
                header.set_size(0);
                tar_builder
                    .append_link(&mut header, rel.as_str(), target)
                    .map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
            }
            DiscoveredNode::Regular {
                dev,
                ino,
                executable,
                size,
                ..
            } => {
                if let Some(prev_path) = first_ino_path.get(&(*dev, *ino)) {
                    header.set_entry_type(tar::EntryType::Link);
                    header.set_mode(if *executable { 0o755 } else { 0o644 });
                    header.set_size(0);
                    tar_builder
                        .append_link(&mut header, rel.as_str(), prev_path.as_str())
                        .map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
                } else {
                    first_ino_path.insert((*dev, *ino), rel.clone());
                    let segs: Vec<&str> = rel.as_str().split('/').collect();
                    let (parents, leaf_slice) = segs.split_at(segs.len() - 1);
                    let parent_fd = open_or_create_dir_nofollow(cache_dir, parents)?;
                    let fd = openat(
                        &parent_fd,
                        leaf_slice[0],
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                        Mode::empty(),
                    )
                    .map_err(|e| SandboxError::CacheRejected(format!("openat `{rel}`: {e}")))?;
                    let f_st = fstat(&fd)
                        .map_err(|e| SandboxError::CacheRejected(format!("fstat `{rel}`: {e}")))?;
                    if FileType::from_raw_mode(f_st.st_mode) != FileType::RegularFile
                        || f_st.st_dev as u64 != *dev
                        || f_st.st_ino != *ino
                    {
                        return Err(SandboxError::CacheRejected(format!(
                            "file `{rel}` mutated during cache packing"
                        )));
                    }
                    let actual_sz = f_st.st_size.max(0) as u64;
                    let _ = size;
                    header.set_entry_type(tar::EntryType::Regular);
                    header.set_mode(if *executable { 0o755 } else { 0o644 });
                    header.set_size(actual_sz);
                    header.set_cksum();
                    let reader = File::from(fd);
                    tar_builder
                        .append_data(&mut header, rel.as_str(), reader.take(actual_sz))
                        .map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
                }
            }
        }
    }

    let zstd_enc = tar_builder
        .into_inner()
        .map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
    let finished_file = zstd_enc
        .finish()
        .map_err(|e| SandboxError::CacheRejected(e.to_string()))?;
    finished_file
        .sync_all()
        .map_err(|e| SandboxError::Io(e.to_string()))?;
    drop(finished_file);

    let (sha256, archive_len) = crate::ghcr::hash_local_file(dest_archive_path)
        .map_err(|e| SandboxError::CacheRejected(format!("failed to hash packed archive: {e}")))?;
    if archive_len > max_bytes {
        let _ = fs::remove_file(dest_archive_path);
        return Err(SandboxError::CacheRejected(format!(
            "packed cache archive size {archive_len} exceeds max_bytes {max_bytes}"
        )));
    }
    Ok(Some((sha256, archive_len)))
}

/// Materializes `<fetch_src>` containing strictly the validated `Cargo.toml`s,
/// `Cargo.lock`, and 0-byte empty stubs at every statically discovered target
/// path (`0` `.cargo/config`, `0` `rust-toolchain`, `0` `.rs` source, `0`
/// `readme`/`license-file`).
pub fn materialize_cargo_locked_fetch_src(
    plan: &CargoLockedFetchPlan,
    fetch_src_dir: &Path,
) -> Result<(), SandboxError> {
    if fetch_src_dir.exists() {
        fs::remove_dir_all(fetch_src_dir).map_err(|e| SandboxError::Io(e.to_string()))?;
    }
    fs::create_dir_all(fetch_src_dir).map_err(|e| SandboxError::Io(e.to_string()))?;

    let write_rel = |rel: &RepoRelPath, bytes: &[u8]| -> Result<(), SandboxError> {
        let dst = fetch_src_dir.join(rel.as_str());
        if let Some(p) = dst.parent() {
            fs::create_dir_all(p).map_err(|e| SandboxError::Io(e.to_string()))?;
        }
        fs::write(&dst, bytes).map_err(|e| SandboxError::Io(e.to_string()))
    };

    write_rel(&plan.lockfile.0, &plan.lockfile.1)?;
    for (mp, mbytes) in &plan.manifests {
        write_rel(mp, mbytes)?;
    }
    for stub in &plan.target_stubs {
        write_rel(stub, b"")?;
    }
    Ok(())
}

/// Builds the `cargo fetch --locked` CLI argument list (`--config net.git-fetch-with-cli=false`
/// + custom `--config registries.<name>.index="..."`).
pub fn build_cargo_fetch_args(
    manifest_arg: &str,
    allowed_registries: &BTreeMap<String, RegistryIndexUrl>,
) -> Vec<String> {
    let mut args = vec![
        "cargo".to_owned(),
        "fetch".to_owned(),
        "--locked".to_owned(),
        "--manifest-path".to_owned(),
        manifest_arg.to_owned(),
        "--config".to_owned(),
        "net.git-fetch-with-cli=false".to_owned(),
    ];
    for (name, idx_url) in allowed_registries {
        if name != "crates-io" {
            args.push("--config".to_owned());
            args.push(format!(
                "registries.{name}.index=\"{}\"",
                idx_url.cargo_cli_index_url()
            ));
        }
    }
    args
}

/// Resolves `RUSTUP_HOME` for containerized `cargo_locked` fetch (`Obligation O9`):
/// preserves `RUSTUP_HOME` from verified `oci_config_env` when present, or
/// falls back to `probed_fallback` (`/usr/local/rustup` / `/root/.rustup`) so
/// `HOME=/empty-cwd` never breaks the `rustup` proxy shim.
pub fn resolve_container_rustup_home(
    oci_config_env: &[String],
    probed_fallback: Option<&str>,
) -> Option<String> {
    let filtered = filter_oci_config_env(oci_config_env);
    filtered
        .get("RUSTUP_HOME")
        .cloned()
        .or_else(|| probed_fallback.map(str::to_owned))
}

/// Resolved local OCI container CLI runtime (`docker` on GitHub Actions runners
/// and Docker workstations; `podman` on rootless Linux workstations/Cloudtops).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerRuntime {
    /// Docker Engine (`docker`), passing `--provenance=false --sbom=false` on
    /// `build` and `save -o` on `save`.
    Docker {
        /// Resolved executable path.
        bin: PathBuf,
    },
    /// Podman (`podman`), passing `--format docker` on `build` (so Dockerfile
    /// `SHELL` directives such as `["/bin/bash", "-euo", "pipefail", "-c"]`
    /// execute identically to Docker Buildx rather than being silently ignored
    /// under Podman's OCI format), `--format oci-archive` on `save`, and
    /// `--userns=keep-id` on `run` when running rootless so high-UID host
    /// users (`uid > 65536`) map cleanly onto bind mounts.
    Podman {
        /// Resolved executable path.
        bin: PathBuf,
        /// `true` iff `podman info --format '{{.Host.Security.Rootless}}'` == `"true"`.
        rootless: bool,
    },
}

fn find_executable_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let cand = dir.join(name);
        if let Ok(meta) = fs::metadata(&cand)
            && meta.is_file()
            && (meta.permissions().mode() & 0o111) != 0
        {
            return Some(cand);
        }
    }
    None
}

fn detect_podman_rootless(bin: &Path) -> bool {
    Command::new(bin)
        .args(["info", "--format", "{{.Host.Security.Rootless}}"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
}

impl ContainerRuntime {
    /// Resolves `CI_CORE_CONTAINER_CLI` if set, otherwise prefers `docker` on
    /// `PATH` and falls back to `podman`.
    pub fn resolve() -> Result<Self, SandboxError> {
        if let Ok(explicit) = std::env::var("CI_CORE_CONTAINER_CLI") {
            let trimmed = explicit.trim();
            if !trimmed.is_empty() {
                let p = if trimmed.contains('/') {
                    PathBuf::from(trimmed)
                } else {
                    find_executable_on_path(trimmed).ok_or_else(|| {
                        SandboxError::Exec(format!(
                            "CI_CORE_CONTAINER_CLI `{trimmed}` not found on PATH"
                        ))
                    })?
                };
                let is_podman = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.contains("podman"));
                return if is_podman {
                    Ok(Self::Podman {
                        rootless: detect_podman_rootless(&p),
                        bin: p,
                    })
                } else {
                    Ok(Self::Docker { bin: p })
                };
            }
        }
        static DEFAULT_RT: std::sync::OnceLock<Option<ContainerRuntime>> =
            std::sync::OnceLock::new();
        let cached = DEFAULT_RT.get_or_init(|| {
            if let Some(bin) = find_executable_on_path("docker") {
                return Some(Self::Docker { bin });
            }
            if let Some(bin) = find_executable_on_path("podman") {
                return Some(Self::Podman {
                    rootless: detect_podman_rootless(&bin),
                    bin,
                });
            }
            None
        });
        cached.clone().ok_or_else(|| {
            SandboxError::Exec(
                "neither `docker` nor `podman` found on PATH (pass `--native` on containerless hosts)"
                    .to_owned(),
            )
        })
    }

    /// Executable path of the container CLI.
    pub fn bin(&self) -> &Path {
        match self {
            Self::Docker { bin } | Self::Podman { bin, .. } => bin,
        }
    }

    /// `true` iff this runtime is rootless Podman requiring `--userns=keep-id`.
    pub const fn needs_keep_id_userns(&self) -> bool {
        matches!(self, Self::Podman { rootless: true, .. })
    }

    /// Builds CLI arguments for `build` producing a single-platform OCI image.
    pub fn build_image_args(
        &self,
        platform_str: &str,
        source_repo_label: &str,
        tag: &str,
        dockerfile: &Path,
        extra_build_args: &[(String, String)],
        ctx_dir: &Path,
    ) -> Vec<String> {
        let mut args = vec!["build".to_owned()];
        match self {
            Self::Docker { .. } => {
                args.extend([
                    "--platform".to_owned(),
                    platform_str.to_owned(),
                    "--provenance=false".to_owned(),
                    "--sbom=false".to_owned(),
                ]);
            }
            Self::Podman { .. } => {
                args.extend([
                    "--format".to_owned(),
                    "docker".to_owned(),
                    "--platform".to_owned(),
                    platform_str.to_owned(),
                ]);
            }
        }
        args.extend([
            "--label".to_owned(),
            format!("org.opencontainers.image.source={source_repo_label}"),
            "-t".to_owned(),
            tag.to_owned(),
            "-f".to_owned(),
            dockerfile.display().to_string(),
        ]);
        for (k, v) in extra_build_args {
            args.extend(["--build-arg".to_owned(), format!("{k}={v}")]);
        }
        args.push(ctx_dir.display().to_string());
        args
    }

    /// Streams `save [--format oci-archive] <tag>` directly into `out_dir`
    /// without materializing an intermediate uncompressed tarball on disk.
    pub fn save_oci_archive_to_dir(&self, tag: &str, out_dir: &Path) -> Result<(), SandboxError> {
        fs::create_dir_all(out_dir).map_err(|e| SandboxError::Io(e.to_string()))?;
        let mut cmd = Command::new(self.bin());
        cmd.arg("save");
        if matches!(self, Self::Podman { .. }) {
            cmd.args(["--format", "oci-archive"]);
        }
        cmd.arg(tag);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| SandboxError::Exec(format!("container save spawn failed: {e}")))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SandboxError::Exec("container save missing stdout".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| SandboxError::Exec("container save missing stderr".to_owned()))?;
        let stderr_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = BufReader::new(stderr).read_to_end(&mut buf);
            buf
        });
        let unpack_res = tar::Archive::new(BufReader::new(stdout)).unpack(out_dir);
        let status = child
            .wait()
            .map_err(|e| SandboxError::Exec(format!("container save wait failed: {e}")))?;
        let stderr_bytes = stderr_thread.join().unwrap_or_default();
        if !status.success() {
            return Err(SandboxError::Exec(format!(
                "container save failed: {}",
                String::from_utf8_lossy(&stderr_bytes).trim()
            )));
        }
        unpack_res.map_err(|e| SandboxError::Io(format!("container save unpack failed: {e}")))?;
        Ok(())
    }

    /// Inspects a locally built/loaded image and returns `(config_id_sha256, config_env)`.
    pub fn inspect_local_image(
        &self,
        reference: &str,
    ) -> Result<(Sha256Digest, Vec<String>), SandboxError> {
        let out = Command::new(self.bin())
            .args(["image", "inspect", reference])
            .output()
            .map_err(|e| SandboxError::Exec(format!("container image inspect failed: {e}")))?;
        if !out.status.success() {
            return Err(SandboxError::Exec(format!(
                "container image inspect failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let arr: serde_json::Value = serde_json::from_slice(&out.stdout)
            .map_err(|e| SandboxError::Exec(format!("invalid image inspect JSON: {e}")))?;
        let first = arr
            .as_array()
            .and_then(|a| a.first())
            .ok_or_else(|| SandboxError::Exec("image inspect returned empty array".to_owned()))?;
        let raw_id = first
            .get("Id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SandboxError::Exec("image inspect missing `Id`".to_owned()))?;
        let hex = raw_id.strip_prefix("sha256:").unwrap_or(raw_id);
        let digest = Sha256Digest::from_hex(hex).map_err(|e| {
            SandboxError::Exec(format!("invalid image `Id` digest `{raw_id}`: {e}"))
        })?;
        let env = first
            .get("Config")
            .and_then(|c| c.get("Env"))
            .and_then(|e| e.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        Ok((digest, env))
    }

    /// Best-effort `rmi -f <tag>`.
    pub fn rmi_force(&self, tag: &str) {
        let _ = Command::new(self.bin()).args(["rmi", "-f", tag]).output();
    }

    /// Checks whether `image_id` (`sha256:<config_hex>`) exists locally.
    pub fn image_exists(&self, image_id: &str) -> bool {
        Command::new(self.bin())
            .args(["image", "inspect", image_id])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}

/// Builds the isolated `docker`/`podman run` argv for pre-sandbox `cargo fetch --locked`
/// (`§5.2` + `Obligations O6 & O9`).
pub fn build_container_cargo_fetch_docker_args(
    (uid, gid): (u32, u32),
    fetch_src_dir: &Path,
    cache_dir: &Path,
    loaded_image_id: &str,
    workspace_manifest: &RepoRelPath,
    allowed_registries: &BTreeMap<String, RegistryIndexUrl>,
    rustup_home: Option<&str>,
) -> Vec<String> {
    build_container_cargo_fetch_args_with_userns(
        (uid, gid),
        false,
        fetch_src_dir,
        cache_dir,
        loaded_image_id,
        workspace_manifest,
        allowed_registries,
        rustup_home,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_container_cargo_fetch_args_with_userns(
    (uid, gid): (u32, u32),
    keep_id_userns: bool,
    fetch_src_dir: &Path,
    cache_dir: &Path,
    loaded_image_id: &str,
    workspace_manifest: &RepoRelPath,
    allowed_registries: &BTreeMap<String, RegistryIndexUrl>,
    rustup_home: Option<&str>,
) -> Vec<String> {
    let mut args = vec![
        "run".to_owned(),
        "--rm".to_owned(),
        "--init".to_owned(),
        "--entrypoint".to_owned(),
        String::new(),
    ];
    if keep_id_userns {
        args.push("--userns=keep-id".to_owned());
    }
    args.extend([
        "--user".to_owned(),
        format!("{uid}:{gid}"),
        "--read-only".to_owned(),
        "--cap-drop=ALL".to_owned(),
        "--security-opt=no-new-privileges:true".to_owned(),
        "--pids-limit=4096".to_owned(),
        "--tmpfs".to_owned(),
        "/empty-cwd:rw,nosuid,nodev".to_owned(),
        "--tmpfs".to_owned(),
        "/tmp:rw,nosuid,nodev".to_owned(),
        "--workdir".to_owned(),
        "/empty-cwd".to_owned(),
        "-e".to_owned(),
        "HOME=/empty-cwd".to_owned(),
        "-e".to_owned(),
        "TMPDIR=/tmp".to_owned(),
        "-e".to_owned(),
        "CARGO_HOME=/cargo-home".to_owned(),
    ]);
    if let Some(rh) = rustup_home {
        args.push("-e".to_owned());
        args.push(format!("RUSTUP_HOME={rh}"));
    }
    args.extend([
        "-v".to_owned(),
        format!("{}:/fetch-src:ro", fetch_src_dir.display()),
        "-v".to_owned(),
        format!("{}:/cargo-home:rw", cache_dir.display()),
        loaded_image_id.to_owned(),
    ]);
    let manifest_in_container = format!("/fetch-src/{}", workspace_manifest.as_str());
    args.extend(build_cargo_fetch_args(
        &manifest_in_container,
        allowed_registries,
    ));
    args
}

/// Runs `cargo fetch --locked` in `run-local --native` mode from an empty
/// external `cwd` (`HOME=<empty_cwd>`) while preserving host `RUSTUP_HOME` /
/// `RUSTUP_TOOLCHAIN` (`Obligation O9`).
pub fn run_cargo_locked_fetch_native(
    plan: &CargoLockedFetchPlan,
    allowed_registries: &BTreeMap<String, RegistryIndexUrl>,
    cache_dir: &Path,
    staging_root: &Path,
    extra_cargo_args: &[&str],
) -> Result<(), SandboxError> {
    let fetch_src = staging_root.join("fetch-src");
    let empty_cwd = staging_root.join("empty-cwd");
    materialize_cargo_locked_fetch_src(plan, &fetch_src)?;
    if empty_cwd.exists() {
        fs::remove_dir_all(&empty_cwd).map_err(|e| SandboxError::Io(e.to_string()))?;
    }
    fs::create_dir_all(&empty_cwd).map_err(|e| SandboxError::Io(e.to_string()))?;
    fs::create_dir_all(cache_dir).map_err(|e| SandboxError::Io(e.to_string()))?;

    let manifest_host = fetch_src.join(plan.workspace_manifest.as_str());
    let fetch_argv = build_cargo_fetch_args(
        manifest_host
            .to_str()
            .ok_or_else(|| SandboxError::Io("non-UTF-8 manifest path".to_owned()))?,
        allowed_registries,
    );

    let mut cmd = Command::new(&fetch_argv[0]);
    cmd.args(&fetch_argv[1..]);
    cmd.args(extra_cargo_args);
    cmd.current_dir(&empty_cwd);
    cmd.env_clear();
    for passthrough in ["PATH", "SSL_CERT_FILE", "SSL_CERT_DIR", "LANG", "LC_ALL"] {
        if let Ok(v) = std::env::var(passthrough) {
            cmd.env(passthrough, v);
        }
    }
    // Obligation `O9`: preserve `RUSTUP_HOME` (or `~/.rustup` derived from the
    // real host `HOME` BEFORE overriding `HOME` to `empty_cwd`) and optional
    // `RUSTUP_TOOLCHAIN`.
    if let Ok(rh) = std::env::var("RUSTUP_HOME") {
        cmd.env("RUSTUP_HOME", rh);
    } else if let Ok(real_home) = std::env::var("HOME") {
        let candidate = PathBuf::from(real_home).join(".rustup");
        if candidate.is_dir() {
            cmd.env("RUSTUP_HOME", candidate);
        }
    }
    if let Ok(rt) = std::env::var("RUSTUP_TOOLCHAIN") {
        cmd.env("RUSTUP_TOOLCHAIN", rt);
    }
    cmd.env("HOME", &empty_cwd);
    cmd.env("TMPDIR", std::env::temp_dir());
    cmd.env("CARGO_HOME", cache_dir);

    let out = cmd
        .output()
        .map_err(|e| SandboxError::CargoFetch(format!("failed to spawn cargo: {e}")))?;
    if !out.status.success() {
        return Err(SandboxError::CargoFetch(format!(
            "cargo fetch --locked exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Runs containerized `cargo_locked` fetch via `docker`/`podman run` (`§5.2` + `O6` + `O9`).
pub fn run_cargo_locked_fetch_container(
    plan: &CargoLockedFetchPlan,
    allowed_registries: &BTreeMap<String, RegistryIndexUrl>,
    cache_dir: &Path,
    staging_root: &Path,
    loaded_image_id: &str,
    oci_config_env: &[String],
) -> Result<(), SandboxError> {
    let rt = ContainerRuntime::resolve()?;
    let fetch_src = staging_root.join("fetch-src");
    materialize_cargo_locked_fetch_src(plan, &fetch_src)?;
    fs::create_dir_all(cache_dir).map_err(|e| SandboxError::Io(e.to_string()))?;

    let mut probed_rh: Option<&str> = None;
    if !oci_config_env.iter().any(|e| e.starts_with("RUSTUP_HOME=")) {
        for cand in ["/usr/local/rustup", "/root/.rustup"] {
            let st = Command::new(rt.bin())
                .args([
                    "run",
                    "--rm",
                    "--entrypoint",
                    "",
                    "--network=none",
                    "--read-only",
                    loaded_image_id,
                    "test",
                    "-d",
                    cand,
                ])
                .status();
            if st.is_ok_and(|s| s.success()) {
                probed_rh = Some(cand);
                break;
            }
        }
    }
    let rustup_home = resolve_container_rustup_home(oci_config_env, probed_rh);
    let docker_args = build_container_cargo_fetch_args_with_userns(
        host_uid_gid(),
        rt.needs_keep_id_userns(),
        &fetch_src,
        cache_dir,
        loaded_image_id,
        &plan.workspace_manifest,
        allowed_registries,
        rustup_home.as_deref(),
    );

    let out = Command::new(rt.bin())
        .args(&docker_args)
        .output()
        .map_err(|e| SandboxError::CargoFetch(format!("container run cargo fetch: {e}")))?;
    if !out.status.success() {
        return Err(SandboxError::CargoFetch(format!(
            "container cargo fetch exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Writes the `docker load` input for a verified layout to `w`: every file
/// under `layout_dir`, plus a synthesized `manifest.json` (see
/// `VerifiedOciLayout::docker_load_manifest_json`). The on-disk layout is
/// not modified, so it stays a pure OCI layout.
pub fn write_docker_load_tar<W: Write>(
    layout_dir: &Path,
    docker_manifest_json: &[u8],
    w: W,
) -> std::io::Result<W> {
    let mut tb = tar::Builder::new(w);
    tb.follow_symlinks(false);
    tb.append_dir_all(".", layout_dir)?;
    let mut hdr = tar::Header::new_gnu();
    hdr.set_size(docker_manifest_json.len() as u64);
    hdr.set_mode(0o644);
    hdr.set_cksum();
    tb.append_data(&mut hdr, "manifest.json", docker_manifest_json)?;
    tb.into_inner()
}

/// Loads a verified pure OCI layout directory into the local container store
/// and returns the pinned `<loaded_image_id> = sha256:<verified_config_digest>`
/// (`Obligation O6`).
///
/// Uses zero-copy `podman load -i <layout_dir>` on Podman and streams a tar
/// directly over stdin on Docker so no multi-GB intermediate `.tar` file is
/// written to `/tmp`.
pub fn docker_load_verified_oci_layout(
    layout_dir: &Path,
    verified: &VerifiedOciLayout,
) -> Result<String, SandboxError> {
    let verified_config_digest = &verified.verified_config_digest;
    let rt = ContainerRuntime::resolve()?;
    match rt {
        ContainerRuntime::Podman { ref bin, .. } => {
            let out = Command::new(bin)
                .arg("load")
                .arg("-i")
                .arg(layout_dir)
                .output()
                .map_err(|e| SandboxError::Exec(format!("container load failed: {e}")))?;
            if !out.status.success() {
                return Err(SandboxError::Exec(format!(
                    "container load exited {:?}: {}",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
        }
        ContainerRuntime::Docker { ref bin } => {
            let docker_manifest_json = verified
                .docker_load_manifest_json()
                .map_err(|e| SandboxError::Exec(format!("docker load manifest: {e}")))?;
            let mut child = Command::new(bin)
                .arg("load")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| SandboxError::Exec(format!("container load spawn failed: {e}")))?;
            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| SandboxError::Exec("container load missing stdin".to_owned()))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| SandboxError::Exec("container load missing stdout".to_owned()))?;
            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| SandboxError::Exec("container load missing stderr".to_owned()))?;
            let out_t = std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = BufReader::new(stdout).read_to_end(&mut buf);
                buf
            });
            let err_t = std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = BufReader::new(stderr).read_to_end(&mut buf);
                buf
            });
            let stream_res =
                write_docker_load_tar(layout_dir, &docker_manifest_json, BufWriter::new(stdin))
                    .and_then(|mut w| w.flush());
            let status = child
                .wait()
                .map_err(|e| SandboxError::Exec(format!("container load wait failed: {e}")))?;
            let _ = out_t.join();
            let err_bytes = err_t.join().unwrap_or_default();
            if !status.success() {
                return Err(SandboxError::Exec(format!(
                    "container load exited {:?}: {}",
                    status.code(),
                    String::from_utf8_lossy(&err_bytes).trim()
                )));
            }
            stream_res
                .map_err(|e| SandboxError::Io(format!("container load stream failed: {e}")))?;
        }
    }
    Ok(verified_config_digest.to_oci_digest())
}

/// Exports a rootfs directory from `loaded_image_id` (`sha256:<config_hex>`)
/// via unprivileged `docker`/`podman create` + streaming `export` (`§5.3`),
/// avoiding any intermediate rootfs tarball on disk.
pub fn export_rootfs_via_docker(
    loaded_image_id: &str,
    rootfs_dir: &Path,
) -> Result<(), SandboxError> {
    let rt = ContainerRuntime::resolve()?;
    if rootfs_dir.exists() {
        fs::remove_dir_all(rootfs_dir).map_err(|e| SandboxError::Io(e.to_string()))?;
    }
    fs::create_dir_all(rootfs_dir).map_err(|e| SandboxError::Io(e.to_string()))?;

    let create_out = Command::new(rt.bin())
        .args(["create", "--entrypoint", "/bin/true", loaded_image_id])
        .output()
        .map_err(|e| SandboxError::Exec(format!("container create: {e}")))?;
    if !create_out.status.success() {
        return Err(SandboxError::Exec(format!(
            "container create failed: {}",
            String::from_utf8_lossy(&create_out.stderr).trim()
        )));
    }
    let cid = String::from_utf8_lossy(&create_out.stdout)
        .trim()
        .to_owned();

    let spawn_res = Command::new(rt.bin())
        .arg("export")
        .arg(&cid)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawn_res {
        Ok(c) => c,
        Err(e) => {
            let _ = Command::new(rt.bin()).args(["rm", "-f", &cid]).output();
            return Err(SandboxError::Exec(format!("container export: {e}")));
        }
    };
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SandboxError::Exec("container export missing stdout".to_owned()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| SandboxError::Exec("container export missing stderr".to_owned()))?;
    let err_t = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = BufReader::new(stderr).read_to_end(&mut buf);
        buf
    });

    let extract_res = extract_tar_stripping_special_reader(BufReader::new(stdout), rootfs_dir);
    let wait_res = child.wait();
    let err_bytes = err_t.join().unwrap_or_default();
    let _ = Command::new(rt.bin()).args(["rm", "-f", &cid]).output();

    let status = wait_res.map_err(|e| SandboxError::Exec(format!("container export wait: {e}")))?;
    if !status.success() {
        return Err(SandboxError::Exec(format!(
            "container export failed: {}",
            String::from_utf8_lossy(&err_bytes).trim()
        )));
    }
    extract_res
}

/// Extracts an exported OCI rootfs tarball into `rootfs_dir`, stripping
/// setuid/setgid/sticky bits and device/FIFO/socket nodes while preserving
/// execute bits on `0o555` binaries (such as Nix store executables) and keeping
/// host directories/files owner-writable for clean teardown (`--ro-bind` locks
/// the rootfs read-only inside `bwrap`).
pub fn extract_tar_stripping_special(
    tar_path: &Path,
    rootfs_dir: &Path,
) -> Result<(), SandboxError> {
    let f = File::open(tar_path).map_err(|e| SandboxError::Io(e.to_string()))?;
    extract_tar_stripping_special_reader(BufReader::new(f), rootfs_dir)
}

/// Streaming version of [`extract_tar_stripping_special`].
pub fn extract_tar_stripping_special_reader<R: Read>(
    reader: R,
    rootfs_dir: &Path,
) -> Result<(), SandboxError> {
    let mut ar = tar::Archive::new(reader);
    for ent_res in ar.entries().map_err(|e| SandboxError::Io(e.to_string()))? {
        let mut ent = ent_res.map_err(|e| SandboxError::Io(e.to_string()))?;
        let raw_p = ent
            .path()
            .map_err(|e| SandboxError::Io(e.to_string()))?
            .into_owned();
        let clean_s = raw_p
            .to_str()
            .unwrap_or_default()
            .trim_start_matches("./")
            .trim_start_matches('/')
            .trim_end_matches('/');
        if clean_s.is_empty() || clean_s.split('/').any(|s| s == "..") {
            continue;
        }
        let dst = rootfs_dir.join(clean_s);
        let etype = ent.header().entry_type();
        let mode = ent.header().mode().unwrap_or(0o644) & 0o777; // strips setuid/setgid/sticky
        if etype.is_dir() {
            fs::create_dir_all(&dst).map_err(|e| SandboxError::Io(e.to_string()))?;
            fs::set_permissions(&dst, fs::Permissions::from_mode((mode | 0o700).max(0o755)))
                .map_err(|e| SandboxError::Io(e.to_string()))?;
        } else if etype.is_file() {
            if let Some(p) = dst.parent() {
                fs::create_dir_all(p).map_err(|e| SandboxError::Io(e.to_string()))?;
            }
            let _ = fs::remove_file(&dst);
            let mut out_f = File::create(&dst).map_err(|e| SandboxError::Io(e.to_string()))?;
            std::io::copy(&mut ent, &mut out_f).map_err(|e| SandboxError::Io(e.to_string()))?;
            fs::set_permissions(&dst, fs::Permissions::from_mode(mode | 0o600))
                .map_err(|e| SandboxError::Io(e.to_string()))?;
        } else if etype.is_symlink() {
            if let Ok(Some(ln)) = ent.link_name() {
                if let Some(p) = dst.parent() {
                    fs::create_dir_all(p).map_err(|e| SandboxError::Io(e.to_string()))?;
                }
                let _ = fs::remove_file(&dst);
                symlink(ln, &dst).map_err(|e| SandboxError::Io(e.to_string()))?;
            }
        } else if etype.is_hard_link()
            && let Ok(Some(ln)) = ent.link_name()
        {
            let target_clean = ln
                .to_str()
                .unwrap_or_default()
                .trim_start_matches("./")
                .trim_start_matches('/');
            let tdst = rootfs_dir.join(target_clean);
            if tdst.is_file() {
                if let Some(p) = dst.parent() {
                    fs::create_dir_all(p).map_err(|e| SandboxError::Io(e.to_string()))?;
                }
                let _ = fs::remove_file(&dst);
                fs::hard_link(&tdst, &dst).map_err(|e| SandboxError::Io(e.to_string()))?;
            }
        }
        // Device/FIFO/socket nodes are intentionally skipped on rootfs export.
    }
    Ok(())
}

///Mount specification shared by `Container` and `NestedBwrap` launchers.
#[derive(Debug, Clone)]
pub struct SandboxLaunchSpec<'a> {
    /// Host staging directory mapped to `/work` (`ro`).
    pub work_dir: &'a Path,
    /// Host empty writable overlays `(host_dir, repo_rel_path)` mapped to `/work/<rel>`.
    pub writable_overlays: &'a [(PathBuf, RepoRelPath)],
    /// Host scratch directory mapped to `/scratch` (`rw`).
    pub scratch_dir: &'a Path,
    /// Host outputs directory mapped to `/outputs` (`rw`).
    pub outputs_dir: &'a Path,
    /// Host cache directories `(host_dir, container_mount)` mapped `rw`.
    pub cache_mounts: &'a [(PathBuf, AbsUnixPath)],
    /// Optional working directory beneath `/work`.
    pub workdir: Option<&'a RepoRelPath>,
    /// Direct `execve` argument vector.
    pub command: &'a [String],
    /// Filtered OCI `Config.Env` merged with check `env` and `PIN_*`.
    pub merged_env: &'a BTreeMap<String, String>,
}

/// Builds the exact `docker`/`podman run` argv for `SandboxMode::Container` (`§5.3`).
pub fn build_container_sandbox_docker_args(
    uid: u32,
    gid: u32,
    loaded_image_id: &str,
    spec: &SandboxLaunchSpec<'_>,
) -> Vec<String> {
    build_container_sandbox_args_with_userns(uid, gid, false, loaded_image_id, spec)
}

fn build_container_sandbox_args_with_userns(
    uid: u32,
    gid: u32,
    keep_id_userns: bool,
    loaded_image_id: &str,
    spec: &SandboxLaunchSpec<'_>,
) -> Vec<String> {
    let container_wd = match spec.workdir {
        None => "/work".to_owned(),
        Some(w) => format!("/work/{}", w.as_str()),
    };
    let mut args = vec![
        "run".to_owned(),
        "--rm".to_owned(),
        "--init".to_owned(),
        "--entrypoint".to_owned(),
        String::new(),
    ];
    if keep_id_userns {
        args.push("--userns=keep-id".to_owned());
    }
    args.extend([
        "--user".to_owned(),
        format!("{uid}:{gid}"),
        "--network=none".to_owned(),
        "--read-only".to_owned(),
        "--cap-drop=ALL".to_owned(),
        "--security-opt=no-new-privileges:true".to_owned(),
        "--pids-limit=4096".to_owned(),
        "--tmpfs".to_owned(),
        "/tmp:rw,exec,nosuid,nodev".to_owned(),
    ]);
    for (k, v) in spec.merged_env {
        args.push("-e".to_owned());
        args.push(format!("{k}={v}"));
    }
    args.push("-v".to_owned());
    args.push(format!("{}:/work:ro", spec.work_dir.display()));
    for (host_ov, rel_ov) in spec.writable_overlays {
        args.push("-v".to_owned());
        args.push(format!(
            "{}:/work/{}:rw",
            host_ov.display(),
            rel_ov.as_str()
        ));
    }
    args.extend([
        "-v".to_owned(),
        format!("{}:/scratch:rw", spec.scratch_dir.display()),
        "-v".to_owned(),
        format!("{}:/outputs:rw", spec.outputs_dir.display()),
    ]);
    for (host_cache, cmount) in spec.cache_mounts {
        args.push("-v".to_owned());
        args.push(format!("{}:{}:rw", host_cache.display(), cmount.as_str()));
    }
    args.extend(["-w".to_owned(), container_wd, loaded_image_id.to_owned()]);
    args.extend(spec.command.iter().cloned());
    args
}

/// Executes a check inside `SandboxMode::Container` and returns `true` iff exit
/// code `0`.
pub fn run_container_sandbox(
    loaded_image_id: &str,
    spec: &SandboxLaunchSpec<'_>,
) -> Result<bool, SandboxError> {
    let rt = ContainerRuntime::resolve()?;
    let (uid, gid) = host_uid_gid();
    let args = build_container_sandbox_args_with_userns(
        uid,
        gid,
        rt.needs_keep_id_userns(),
        loaded_image_id,
        spec,
    );
    let status = Command::new(rt.bin())
        .args(&args)
        .status()
        .map_err(|e| SandboxError::Exec(format!("container run failed: {e}")))?;
    Ok(status.success())
}

/// Resolves the `bwrap` executable: checks `CI_CORE_BWRAP_BIN` first, then
/// prefers sibling static `bwrap` in the `ci-core` binary directory
/// (`$RUNNER_TEMP/ci-core/<sha>/bwrap`), falling back to `/usr/bin/bwrap` in
/// local developer builds.
pub fn resolve_bwrap_binary() -> Result<PathBuf, SandboxError> {
    if let Ok(explicit) = std::env::var("CI_CORE_BWRAP_BIN")
        && !explicit.trim().is_empty()
    {
        let p = PathBuf::from(&explicit);
        let meta = fs::metadata(&p).map_err(|e| {
            SandboxError::Exec(format!(
                "CI_CORE_BWRAP_BIN `{explicit}` does not exist or is unreadable: {e}"
            ))
        })?;
        if !meta.is_file() || (meta.permissions().mode() & 0o111) == 0 {
            return Err(SandboxError::Exec(format!(
                "CI_CORE_BWRAP_BIN `{explicit}` is not an executable regular file"
            )));
        }
        return Ok(p);
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let bundled = dir.join("bwrap");
        if bundled.is_file() {
            return Ok(bundled);
        }
    }
    let sys_bwrap = PathBuf::from("/usr/bin/bwrap");
    if sys_bwrap.is_file() {
        return Ok(sys_bwrap);
    }
    Err(SandboxError::Exec(
        "bubblewrap (`bwrap`) binary not found via CI_CORE_BWRAP_BIN, alongside `ci-core`, or at `/usr/bin/bwrap`"
            .to_owned(),
    ))
}

/// Runs the unprivileged user-namespace preflight check
/// `<bwrap> --ro-bind / / --unshare-all --cap-drop ALL -- true`.
pub fn verify_bwrap_userns_preflight(bwrap_bin: &Path) -> Result<(), SandboxError> {
    let out = Command::new(bwrap_bin)
        .args([
            "--ro-bind",
            "/",
            "/",
            "--unshare-all",
            "--cap-drop",
            "ALL",
            "--",
            "/bin/true",
        ])
        .output()
        .map_err(|e| SandboxError::Exec(format!("bwrap preflight spawn failed: {e}")))?;
    if !out.status.success() {
        return Err(SandboxError::Exec(format!(
            "bwrap userns preflight failed ({:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Pre-creates mountpoint directories (and `etc/{passwd,group}` file mount
/// targets when absent) inside an exported `rootfs_dir` strictly with
/// `O_NOFOLLOW` before launching outer `bwrap` (`§5.3`).
pub fn precreate_bwrap_rootfs_mountpoints(
    rootfs_dir: &Path,
    cache_mounts: &[(PathBuf, AbsUnixPath)],
) -> Result<(), SandboxError> {
    for fixed in ["dev", "proc", "tmp", "work", "scratch", "outputs"] {
        let _ = open_or_create_dir_nofollow(rootfs_dir, &[fixed])?;
    }
    let etc_fd = open_or_create_dir_nofollow(rootfs_dir, &["etc"])?;
    for name in ["passwd", "group"] {
        match openat(
            &etc_fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(fd) => {
                let st =
                    fstat(&fd).map_err(|e| SandboxError::Io(format!("fstat `etc/{name}`: {e}")))?;
                if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
                    return Err(SandboxError::Io(format!(
                        "`etc/{name}` in rootfs is not a regular file"
                    )));
                }
            }
            Err(rustix::io::Errno::NOENT) => {
                let _ = openat(
                    &etc_fd,
                    name,
                    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW,
                    Mode::from_raw_mode(0o644),
                )
                .map_err(|e| SandboxError::Io(format!("create `etc/{name}` mount target: {e}")))?;
            }
            Err(e) => {
                return Err(SandboxError::Io(format!(
                    "open `etc/{name}` in rootfs (symlinks forbidden): {e}"
                )));
            }
        }
    }
    for (_, cmount) in cache_mounts {
        let segs: Vec<&str> = cmount.as_str()[1..].split('/').collect();
        let _ = open_or_create_dir_nofollow(rootfs_dir, &segs)?;
    }
    Ok(())
}

fn read_rootfs_etc_file_nofollow(rootfs_dir: &Path, name: &str) -> Result<String, SandboxError> {
    let etc_fd = match openat(
        CWD,
        rootfs_dir.join("etc"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(String::new()),
        Err(e) => {
            return Err(SandboxError::Io(format!(
                "open `{}/etc` (symlinks forbidden): {e}",
                rootfs_dir.display()
            )));
        }
    };
    match openat(
        &etc_fd,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(fd) => {
            let st =
                fstat(&fd).map_err(|e| SandboxError::Io(format!("fstat `etc/{name}`: {e}")))?;
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
                return Err(SandboxError::Io(format!(
                    "`etc/{name}` in rootfs is not a regular file"
                )));
            }
            let mut f = File::from(fd);
            let mut out = String::new();
            f.read_to_string(&mut out)
                .map_err(|e| SandboxError::Io(format!("read `etc/{name}`: {e}")))?;
            Ok(out)
        }
        Err(rustix::io::Errno::NOENT) => Ok(String::new()),
        Err(e) => Err(SandboxError::Io(format!(
            "open `etc/{name}` (symlinks forbidden): {e}"
        ))),
    }
}

/// Synthesizes ephemeral read-only `/etc/passwd` and `/etc/group` files for
/// `SandboxMode::NestedBwrap` so processes that clear `$HOME` (`env -i` /
/// `Command::env_clear()`) still resolve `getpwuid_r(getuid())` to `pw_dir =
/// "/scratch"` regardless of the host runner UID (`1001` on GitHub Actions,
/// `1000` on developer workstations, or high corporate UIDs) without mutating
/// the cached `rootfs_dir`.
fn synthesize_bwrap_identity_files(
    rootfs_dir: &Path,
    uid: u32,
    gid: u32,
) -> Result<(tempfile::TempDir, PathBuf, PathBuf), SandboxError> {
    let base_passwd = read_rootfs_etc_file_nofollow(rootfs_dir, "passwd")?;
    let base_group = read_rootfs_etc_file_nofollow(rootfs_dir, "group")?;
    let uid_s = uid.to_string();
    let gid_s = gid.to_string();

    let mut passwd_lines: Vec<String> = Vec::new();
    let mut saw_root_user = false;
    for raw in base_passwd.lines() {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let mut fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 7 {
            if fields[2] == "0" {
                saw_root_user = true;
                if uid == 0 {
                    fields[5] = "/scratch";
                    passwd_lines.push(fields.join(":"));
                    continue;
                }
            } else if uid != 0 && (fields[2] == uid_s || fields[0] == "ci-sandbox") {
                continue;
            }
        }
        passwd_lines.push(line.to_owned());
    }
    if !saw_root_user {
        let root_home = if uid == 0 { "/scratch" } else { "/root" };
        passwd_lines.insert(0, format!("root:x:0:0:root:{root_home}:/bin/sh"));
    }
    if uid != 0 {
        passwd_lines.push(format!(
            "ci-sandbox:x:{uid}:{gid}:ci-core sandbox:/scratch:/sbin/nologin"
        ));
    }

    let mut group_lines: Vec<String> = Vec::new();
    let mut saw_root_group = false;
    for raw in base_group.lines() {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 {
            if fields[2] == "0" {
                saw_root_group = true;
            } else if gid != 0 && (fields[2] == gid_s || fields[0] == "ci-sandbox") {
                continue;
            }
        }
        group_lines.push(line.to_owned());
    }
    if !saw_root_group {
        group_lines.insert(0, "root:x:0:".to_owned());
    }
    if gid != 0 {
        group_lines.push(format!("ci-sandbox:x:{gid}:"));
    }

    let td = tempfile::Builder::new()
        .prefix("ci-core-bwrap-id-")
        .tempdir()
        .map_err(|e| SandboxError::Io(format!("create ephemeral identity dir: {e}")))?;
    let passwd_path = td.path().join("passwd");
    let group_path = td.path().join("group");
    let mut passwd_content = passwd_lines.join("\n");
    passwd_content.push('\n');
    let mut group_content = group_lines.join("\n");
    group_content.push('\n');
    fs::write(&passwd_path, passwd_content)
        .map_err(|e| SandboxError::Io(format!("write synthesized passwd: {e}")))?;
    fs::set_permissions(&passwd_path, fs::Permissions::from_mode(0o644))
        .map_err(|e| SandboxError::Io(e.to_string()))?;
    fs::write(&group_path, group_content)
        .map_err(|e| SandboxError::Io(format!("write synthesized group: {e}")))?;
    fs::set_permissions(&group_path, fs::Permissions::from_mode(0o644))
        .map_err(|e| SandboxError::Io(e.to_string()))?;

    Ok((td, passwd_path, group_path))
}

/// Builds the exact `bwrap` argv for `SandboxMode::NestedBwrap` (`§5.3`).
pub fn build_nested_bwrap_args(rootfs_dir: &Path, spec: &SandboxLaunchSpec<'_>) -> Vec<String> {
    build_nested_bwrap_args_with_identity(rootfs_dir, None, spec)
}

fn build_nested_bwrap_args_with_identity(
    rootfs_dir: &Path,
    identity_files: Option<(&Path, &Path)>,
    spec: &SandboxLaunchSpec<'_>,
) -> Vec<String> {
    let container_wd = match spec.workdir {
        None => "/work".to_owned(),
        Some(w) => format!("/work/{}", w.as_str()),
    };
    let mut args = vec![
        "--unshare-all".to_owned(),
        "--cap-drop".to_owned(),
        "ALL".to_owned(),
        "--die-with-parent".to_owned(),
        "--new-session".to_owned(),
        "--clearenv".to_owned(),
        "--ro-bind".to_owned(),
        rootfs_dir.display().to_string(),
        "/".to_owned(),
    ];
    if let Some((passwd_path, group_path)) = identity_files {
        args.extend([
            "--ro-bind".to_owned(),
            passwd_path.display().to_string(),
            "/etc/passwd".to_owned(),
            "--ro-bind".to_owned(),
            group_path.display().to_string(),
            "/etc/group".to_owned(),
        ]);
    }
    args.extend([
        "--dev".to_owned(),
        "/dev".to_owned(),
        "--proc".to_owned(),
        "/proc".to_owned(),
        "--tmpfs".to_owned(),
        "/tmp".to_owned(),
        "--ro-bind".to_owned(),
        spec.work_dir.display().to_string(),
        "/work".to_owned(),
    ]);
    for (host_ov, rel_ov) in spec.writable_overlays {
        args.extend([
            "--bind".to_owned(),
            host_ov.display().to_string(),
            format!("/work/{}", rel_ov.as_str()),
        ]);
    }
    args.extend([
        "--bind".to_owned(),
        spec.scratch_dir.display().to_string(),
        "/scratch".to_owned(),
        "--bind".to_owned(),
        spec.outputs_dir.display().to_string(),
        "/outputs".to_owned(),
    ]);
    for (host_cache, cmount) in spec.cache_mounts {
        args.extend([
            "--bind".to_owned(),
            host_cache.display().to_string(),
            cmount.as_str().to_owned(),
        ]);
    }
    args.extend(["--chdir".to_owned(), container_wd]);
    for (k, v) in spec.merged_env {
        args.extend(["--setenv".to_owned(), k.clone(), v.clone()]);
    }
    args.push("--".to_owned());
    args.extend(spec.command.iter().cloned());
    args
}

/// Executes a check inside `SandboxMode::NestedBwrap` over `rootfs_dir` and
/// returns `true` iff exit code `0`.
pub fn run_nested_bwrap_sandbox(
    bwrap_bin: &Path,
    rootfs_dir: &Path,
    spec: &SandboxLaunchSpec<'_>,
) -> Result<bool, SandboxError> {
    verify_bwrap_userns_preflight(bwrap_bin)?;
    if rootfs_dir != Path::new("/") {
        precreate_bwrap_rootfs_mountpoints(rootfs_dir, spec.cache_mounts)?;
    }
    let (uid, gid) = host_uid_gid();
    let (_id_guard, passwd_path, group_path) =
        synthesize_bwrap_identity_files(rootfs_dir, uid, gid)?;
    let args =
        build_nested_bwrap_args_with_identity(rootfs_dir, Some((&passwd_path, &group_path)), spec);
    let status = Command::new(bwrap_bin)
        .env_clear()
        .args(&args)
        .status()
        .map_err(|e| SandboxError::Exec(format!("bwrap launch failed: {e}")))?;
    Ok(status.success())
}

/// Executes a check in opt-in `run-local --native` (`LocalRunMode::NativeUnsandboxed`)
/// mode (`§5.3`), rewriting virtual `/scratch`, `/outputs`, and `<cache.mount>`
/// path values in check `env` to local temporary directories while preserving
/// host `RUSTUP_HOME` (`Obligation O9`).
pub fn run_native_unsandboxed(spec: &SandboxLaunchSpec<'_>) -> Result<bool, SandboxError> {
    eprintln!(
        "warning: running in opt-in `--native` unsandboxed mode (no container or network isolation)"
    );
    let host_cwd = match spec.workdir {
        None => spec.work_dir.to_path_buf(),
        Some(w) => spec.work_dir.join(w.as_str()),
    };

    let mut path_rewrites: Vec<(String, String)> = vec![
        (
            "/scratch".to_owned(),
            spec.scratch_dir.display().to_string(),
        ),
        (
            "/outputs".to_owned(),
            spec.outputs_dir.display().to_string(),
        ),
    ];
    for (host_cache, cmount) in spec.cache_mounts {
        path_rewrites.push((cmount.as_str().to_owned(), host_cache.display().to_string()));
    }
    // Rewrite longest virtual prefixes first.
    path_rewrites.sort_by_key(|a| std::cmp::Reverse(a.0.len()));

    let rewrite_val = |v: &str| -> String {
        for (virt, host) in &path_rewrites {
            if v == virt {
                return host.clone();
            }
            if let Some(rest) = v.strip_prefix(virt)
                && rest.starts_with('/')
            {
                return format!("{host}{rest}");
            }
        }
        v.to_owned()
    };

    let mut cmd = Command::new(&spec.command[0]);
    cmd.args(&spec.command[1..]);
    cmd.current_dir(&host_cwd);
    cmd.env_clear();
    for passthrough in [
        "PATH",
        "LANG",
        "LC_ALL",
        "TERM",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ] {
        if let Ok(pv) = std::env::var(passthrough) {
            cmd.env(passthrough, pv);
        }
    }
    // Obligation `O9`: preserve host `RUSTUP_HOME` / `~/.rustup` when `HOME` is
    // overridden to `scratch_dir`.
    if let Ok(rh) = std::env::var("RUSTUP_HOME") {
        cmd.env("RUSTUP_HOME", rh);
    } else if let Ok(real_home) = std::env::var("HOME") {
        let cand = PathBuf::from(real_home).join(".rustup");
        if cand.is_dir() {
            cmd.env("RUSTUP_HOME", cand);
        }
    }
    if let Ok(rt) = std::env::var("RUSTUP_TOOLCHAIN") {
        cmd.env("RUSTUP_TOOLCHAIN", rt);
    }

    for (k, v) in spec.merged_env {
        cmd.env(k, rewrite_val(v));
    }
    cmd.env("HOME", spec.scratch_dir);
    cmd.env("TMPDIR", std::env::temp_dir());

    let status = cmd
        .status()
        .map_err(|e| SandboxError::Exec(format!("native command spawn failed: {e}")))?;
    Ok(status.success())
}
