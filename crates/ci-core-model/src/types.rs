//! Validated domain types and proof-carrying representations for `ci-core`.
//!
//! Types in this module parse untrusted strings or wire structures at
//! construction and `serde` boundaries so downstream pure planners, digest
//! builders, and gate evaluators can rely on their invariants without
//! re-validating raw inputs.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Deref;

use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Validation error returned when constructing a refined domain value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TypeError {
    /// A collection required to have at least one element was empty.
    #[error("collection must not be empty")]
    EmptyCollection,
    /// A hex-encoded digest had an invalid length or non-lowercase-hex byte.
    #[error("invalid {kind} hex digest {value:?}: {reason}")]
    InvalidDigest {
        /// Digest kind (`sha256` or `git_oid`).
        kind: &'static str,
        /// Rejected input string.
        value: String,
        /// Human-readable rejection reason.
        reason: &'static str,
    },
    /// A repository slug failed `<owner>/<repo>` validation.
    #[error("invalid repository slug {0:?}")]
    InvalidRepoSlug(String),
    /// A repository-relative POSIX path failed normalization or safety checks.
    #[error("invalid repo-relative path {path:?}: {reason}")]
    InvalidRepoRelPath {
        /// Rejected path string.
        path: String,
        /// Human-readable rejection reason.
        reason: &'static str,
    },
    /// An absolute POSIX path failed normalization or safety checks.
    #[error("invalid absolute unix path {path:?}: {reason}")]
    InvalidAbsUnixPath {
        /// Rejected path string.
        path: String,
        /// Human-readable rejection reason.
        reason: &'static str,
    },
    /// An identifier failed character-set or length validation.
    #[error("invalid {kind} {value:?}")]
    InvalidIdentifier {
        /// Identifier kind (`check_id`, `image_id`, `pin_id`, etc.).
        kind: &'static str,
        /// Rejected identifier string.
        value: String,
    },
    /// A 72-character GHCR lookup tag failed prefix or hex validation.
    #[error("invalid lookup tag {0:?}")]
    InvalidLookupTag(String),
    /// A workflow URI failed `<owner>/<repo>/.github/workflows/<file>.y[a]ml`.
    #[error("invalid workflow URI {0:?}")]
    InvalidWorkflowUri(String),
    /// A Cargo registry index URL failed HTTPS scheme validation.
    #[error("invalid registry index URL {0:?}")]
    InvalidRegistryIndexUrl(String),
    /// A `.github/CODEOWNERS` principal failed `@user` or `@org/team` checks.
    #[error("invalid CODEOWNERS principal {0:?}")]
    InvalidCodeOwnerPrincipal(String),
    /// A platform string was neither `linux/amd64` nor `linux/arm64`.
    #[error("unsupported container platform {0:?}")]
    InvalidPlatform(String),
    /// A `ControlPlaneTransition` had identical base and candidate policies.
    #[error("control-plane transition requires base != candidate")]
    TrivialControlPlaneTransition,
}

/// Non-empty vector whose invariant (`!is_empty()`) holds at construction and
/// deserialization boundaries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonEmptyVec<T>(Vec<T>);

impl<T> NonEmptyVec<T> {
    /// Constructs a `NonEmptyVec` if `items` has at least one element.
    pub fn new(items: Vec<T>) -> Result<Self, TypeError> {
        if items.is_empty() {
            return Err(TypeError::EmptyCollection);
        }
        Ok(Self(items))
    }

    /// Constructs a single-element `NonEmptyVec`.
    pub fn singleton(item: T) -> Self {
        Self(vec![item])
    }

    /// Returns the first element, which is always present.
    pub fn first(&self) -> &T {
        &self.0[0]
    }

    /// Returns the underlying slice.
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Consumes `self` and returns the underlying vector.
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T> Deref for NonEmptyVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, T> IntoIterator for &'a NonEmptyVec<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T> IntoIterator for NonEmptyVec<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Serialize> Serialize for NonEmptyVec<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for NonEmptyVec<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = Vec::<T>::deserialize(deserializer)?;
        Self::new(items).map_err(serde::de::Error::custom)
    }
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Validated 32-byte SHA-256 digest serialized as 64 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Wraps raw 32-byte SHA-256 output.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Hashes `data` with SHA-256.
    pub fn hash_bytes(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let out = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        Self(arr)
    }

    /// Parses a strict 64-character lowercase hex SHA-256 string.
    pub fn from_hex(s: &str) -> Result<Self, TypeError> {
        if s.len() != 64 {
            return Err(TypeError::InvalidDigest {
                kind: "sha256",
                value: s.to_owned(),
                reason: "expected 64 lowercase hex characters",
            });
        }
        if !is_lower_hex(s) {
            return Err(TypeError::InvalidDigest {
                kind: "sha256",
                value: s.to_owned(),
                reason: "must contain only [0-9a-f]",
            });
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes).map_err(|_| TypeError::InvalidDigest {
            kind: "sha256",
            value: s.to_owned(),
            reason: "hex decode failed",
        })?;
        Ok(Self(bytes))
    }

    /// Parses an OCI `sha256:<64-lower-hex>` digest string.
    pub fn from_oci_digest(s: &str) -> Result<Self, TypeError> {
        let hex_part = s
            .strip_prefix("sha256:")
            .ok_or_else(|| TypeError::InvalidDigest {
                kind: "sha256",
                value: s.to_owned(),
                reason: "expected sha256: prefix",
            })?;
        Self::from_hex(hex_part)
    }

    /// Returns the raw 32-byte array.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Formats the digest as 64 lowercase hex characters.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Returns the first 16 lowercase hex characters for artifact suffixes.
    pub fn prefix16(&self) -> String {
        let full = self.to_hex();
        full[..16].to_owned()
    }

    /// Formats the digest as `sha256:<64-lower-hex>` for OCI manifests.
    pub fn to_oci_digest(&self) -> String {
        format!("sha256:{}", self.to_hex())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Digest({})", self.to_hex())
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Validated 20-byte Git SHA-1 object ID serialized as 40 lowercase hex chars.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitOid([u8; 20]);

impl GitOid {
    /// Wraps raw 20-byte SHA-1 object ID bytes.
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Parses a strict 40-character lowercase hex Git OID, rejecting branch or
    /// tag names, uppercase hex, and abbreviated hashes.
    pub fn from_hex(s: &str) -> Result<Self, TypeError> {
        if s.len() != 40 {
            return Err(TypeError::InvalidDigest {
                kind: "git_oid",
                value: s.to_owned(),
                reason: "expected 40 lowercase hex characters",
            });
        }
        if !is_lower_hex(s) {
            return Err(TypeError::InvalidDigest {
                kind: "git_oid",
                value: s.to_owned(),
                reason: "must contain only [0-9a-f]",
            });
        }
        let mut bytes = [0u8; 20];
        hex::decode_to_slice(s, &mut bytes).map_err(|_| TypeError::InvalidDigest {
            kind: "git_oid",
            value: s.to_owned(),
            reason: "hex decode failed",
        })?;
        Ok(Self(bytes))
    }

    /// Returns the raw 20-byte array.
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Formats the OID as 40 lowercase hex characters.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for GitOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GitOid({})", self.to_hex())
    }
}

impl fmt::Display for GitOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for GitOid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for GitOid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

fn is_valid_slug_segment(seg: &str) -> bool {
    !seg.is_empty()
        && seg != "."
        && seg != ".."
        && seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Validated `<Owner>/<Repo>` slug paired with its ASCII-lowercased OCI path.
///
/// Both fields are private so `oci_path` is guaranteed to equal
/// `canonical.to_ascii_lowercase()` across construction and deserialization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepoSlug {
    canonical: String,
    oci_path: String,
}

impl RepoSlug {
    /// Parses `<Owner>/<Repo>` and derives the lowercase OCI repository path.
    pub fn new(s: &str) -> Result<Self, TypeError> {
        let Some((owner, repo)) = s.split_once('/') else {
            return Err(TypeError::InvalidRepoSlug(s.to_owned()));
        };
        if repo.contains('/') || !is_valid_slug_segment(owner) || !is_valid_slug_segment(repo) {
            return Err(TypeError::InvalidRepoSlug(s.to_owned()));
        }
        Ok(Self {
            canonical: s.to_owned(),
            oci_path: s.to_ascii_lowercase(),
        })
    }

    /// Exact canonical `<Owner>/<Repo>` configured in `checks.toml`.
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// Lowercased `<owner>/<repo>` required by OCI Distribution v2 paths.
    pub fn oci_path(&self) -> &str {
        &self.oci_path
    }

    /// Owner component of `<Owner>/<Repo>`.
    pub fn owner(&self) -> &str {
        self.canonical
            .split_once('/')
            .map(|(o, _)| o)
            .unwrap_or_default()
    }

    /// Repository component of `<Owner>/<Repo>`.
    pub fn repo(&self) -> &str {
        self.canonical
            .split_once('/')
            .map(|(_, r)| r)
            .unwrap_or_default()
    }

    /// Canonical `https://github.com/<Owner>/<Repo>` URL used in OCI labels.
    pub fn source_repo_url(&self) -> String {
        format!("https://github.com/{}", self.canonical)
    }

    /// Default public CAS GHCR repository (`ghcr.io/<lower_slug>/ci-cas`).
    pub fn default_cas_repo(&self) -> String {
        format!("ghcr.io/{}/ci-cas", self.oci_path)
    }

    /// Default private cache GHCR repository (`ghcr.io/<lower_slug>/ci-cache`).
    pub fn default_cache_repo(&self) -> String {
        format!("ghcr.io/{}/ci-cache", self.oci_path)
    }
}

impl fmt::Display for RepoSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

impl Serialize for RepoSlug {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.canonical)
    }
}

impl<'de> Deserialize<'de> for RepoSlug {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

/// Normalized, non-empty POSIX repository-relative path.
///
/// Forbids leading or trailing slashes, empty segments, `.` or `..` segments,
/// NUL bytes, backslashes, and `.git` components.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepoRelPath(String);

impl RepoRelPath {
    /// Validates a normalized POSIX repository-relative path.
    pub fn new(s: &str) -> Result<Self, TypeError> {
        if s.is_empty() {
            return Err(TypeError::InvalidRepoRelPath {
                path: s.to_owned(),
                reason: "path must not be empty",
            });
        }
        if s.contains('\0') || s.contains('\\') {
            return Err(TypeError::InvalidRepoRelPath {
                path: s.to_owned(),
                reason: "NUL and backslash bytes are forbidden",
            });
        }
        if s.starts_with('/') || s.ends_with('/') {
            return Err(TypeError::InvalidRepoRelPath {
                path: s.to_owned(),
                reason: "leading and trailing slashes are forbidden",
            });
        }
        for seg in s.split('/') {
            if seg.is_empty() || seg == "." || seg == ".." {
                return Err(TypeError::InvalidRepoRelPath {
                    path: s.to_owned(),
                    reason: "empty, '.', and '..' segments are forbidden",
                });
            }
            if seg == ".git" {
                return Err(TypeError::InvalidRepoRelPath {
                    path: s.to_owned(),
                    reason: ".git components are forbidden",
                });
            }
        }
        Ok(Self(s.to_owned()))
    }

    /// Returns the validated POSIX relative path string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if `self` is equal to `other` or a directory ancestor of
    /// `other` under POSIX path-component semantics.
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        if self.0 == other.0 {
            return true;
        }
        other
            .0
            .strip_prefix(&self.0)
            .is_some_and(|rest| rest.starts_with('/'))
    }

    /// Returns `true` if neither `self` nor `other` is a component prefix of
    /// the other.
    pub fn is_prefix_disjoint(&self, other: &Self) -> bool {
        !self.is_prefix_of(other) && !other.is_prefix_of(self)
    }

    /// Returns the parent directory if `self` has more than one component, or
    /// `None` when `self` is at the repository root.
    pub fn parent(&self) -> Option<Self> {
        self.0
            .rsplit_once('/')
            .map(|(prefix, _)| Self(prefix.to_owned()))
    }

    /// Returns all proper non-root directory prefixes of `self` from outermost
    /// to innermost (for `"a/b/c"`, returns `["a", "a/b"]`).
    pub fn proper_ancestors(&self) -> Vec<Self> {
        let mut out = Vec::new();
        let mut acc = String::new();
        let mut iter = self.0.split('/').peekable();
        while let Some(seg) = iter.next() {
            if iter.peek().is_none() {
                break;
            }
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(seg);
            out.push(Self(acc.clone()));
        }
        out
    }

    /// Joins `child` beneath `self`.
    pub fn join(&self, child: &Self) -> Self {
        Self(format!("{}/{}", self.0, child.0))
    }

    /// Joins a single validated filename or directory segment beneath `self`.
    pub fn join_segment(&self, segment: &str) -> Result<Self, TypeError> {
        Self::new(&format!("{}/{}", self.0, segment))
    }

    /// Returns the final path component.
    pub fn file_name(&self) -> &str {
        self.0.rsplit_once('/').map(|(_, f)| f).unwrap_or(&self.0)
    }
}

impl fmt::Display for RepoRelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for RepoRelPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RepoRelPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

/// Normalized absolute POSIX path (`/` or `/a/b`), forbidding `.`, `..`, NUL,
/// and redundant slashes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbsUnixPath(String);

impl AbsUnixPath {
    /// Validates a normalized absolute POSIX path.
    pub fn new(s: &str) -> Result<Self, TypeError> {
        if !s.starts_with('/') {
            return Err(TypeError::InvalidAbsUnixPath {
                path: s.to_owned(),
                reason: "must start with '/'",
            });
        }
        if s.contains('\0') {
            return Err(TypeError::InvalidAbsUnixPath {
                path: s.to_owned(),
                reason: "NUL byte is forbidden",
            });
        }
        if s == "/" {
            return Ok(Self("/".to_owned()));
        }
        if s.ends_with('/') {
            return Err(TypeError::InvalidAbsUnixPath {
                path: s.to_owned(),
                reason: "trailing slash is forbidden on non-root paths",
            });
        }
        for seg in &s[1..].split('/').collect::<Vec<_>>() {
            if seg.is_empty() || *seg == "." || *seg == ".." {
                return Err(TypeError::InvalidAbsUnixPath {
                    path: s.to_owned(),
                    reason: "empty, '.', and '..' segments are forbidden",
                });
            }
        }
        Ok(Self(s.to_owned()))
    }

    /// Returns the underlying absolute POSIX path string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Component-wise prefix check (`"/"` is a prefix of every absolute path).
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        if self.0 == "/" || self.0 == other.0 {
            return true;
        }
        other
            .0
            .strip_prefix(&self.0)
            .is_some_and(|rest| rest.starts_with('/'))
    }

    /// Returns `true` if neither path is a component prefix of the other.
    pub fn is_prefix_disjoint(&self, other: &Self) -> bool {
        !self.is_prefix_of(other) && !other.is_prefix_of(self)
    }
}

impl fmt::Display for AbsUnixPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for AbsUnixPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AbsUnixPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

fn validate_lower_ident(s: &str, max_len: usize, kind: &'static str) -> Result<(), TypeError> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > max_len {
        return Err(TypeError::InvalidIdentifier {
            kind,
            value: s.to_owned(),
        });
    }
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(TypeError::InvalidIdentifier {
            kind,
            value: s.to_owned(),
        });
    }
    if !bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(TypeError::InvalidIdentifier {
            kind,
            value: s.to_owned(),
        });
    }
    Ok(())
}

fn validate_pin_token(s: &str, kind: &'static str) -> Result<(), TypeError> {
    // Matches `\A[a-z0-9](?:[a-z0-9]|[-_][a-z0-9])*\z` with `1 <= len <= 128`:
    // starts and ends with `[a-z0-9]` and contains no consecutive `[-_]` so
    // `norm(s)` never contains `"__"` while accommodating real-world Cargo
    // toolchain/feature names (e.g. 53-char build-rs probe keys).
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return Err(TypeError::InvalidIdentifier {
            kind,
            value: s.to_owned(),
        });
    }
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_alnum(bytes[0]) {
        return Err(TypeError::InvalidIdentifier {
            kind,
            value: s.to_owned(),
        });
    }
    let mut i = 1;
    while i < bytes.len() {
        if is_alnum(bytes[i]) {
            i += 1;
        } else if matches!(bytes[i], b'-' | b'_') {
            if i + 1 >= bytes.len() || !is_alnum(bytes[i + 1]) {
                return Err(TypeError::InvalidIdentifier {
                    kind,
                    value: s.to_owned(),
                });
            }
            i += 2;
        } else {
            return Err(TypeError::InvalidIdentifier {
                kind,
                value: s.to_owned(),
            });
        }
    }
    Ok(())
}

macro_rules! string_id_type {
    ($(#[$meta:meta])* $name:ident, $validator:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Parses and validates an identifier.
            pub fn new(s: &str) -> Result<Self, TypeError> {
                ($validator)(s)?;
                Ok(Self(s.to_owned()))
            }

            /// Returns the validated string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                Self::new(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

string_id_type!(
    /// Check identifier (`^[a-z0-9][a-z0-9._-]{0,239}$`, at most 240 bytes).
    CheckId,
    |s: &str| validate_lower_ident(s, 240, "check_id")
);

string_id_type!(
    /// Container image identifier (`^[a-z0-9][a-z0-9._-]{0,63}$`).
    ImageId,
    |s: &str| validate_lower_ident(s, 64, "image_id")
);

string_id_type!(
    /// Attested cache slot identifier (`^[a-z0-9][a-z0-9._-]{0,63}$`).
    CacheSlotId,
    |s: &str| validate_lower_ident(s, 64, "cache_slot_id")
);

string_id_type!(
    /// Data-pin table identifier (`^[a-z0-9](?:[a-z0-9]|[-_][a-z0-9])*$`, <=128 B).
    PinId,
    |s: &str| validate_pin_token(s, "pin_id")
);

impl PinId {
    /// Uppercases ASCII characters and maps `-` to `_` (`__`-free).
    pub fn norm(&self) -> String {
        self.0.to_ascii_uppercase().replace('-', "_")
    }
}

string_id_type!(
    /// Data-pin key identifier (`^[a-z0-9](?:[a-z0-9]|[-_][a-z0-9])*$`, <=128 B).
    PinKey,
    |s: &str| validate_pin_token(s, "pin_key")
);

impl PinKey {
    /// Uppercases ASCII characters and maps `-` to `_` (`__`-free).
    pub fn norm(&self) -> String {
        self.0.to_ascii_uppercase().replace('-', "_")
    }
}

/// Projects `(pin, key)` to `PIN_<NORM_PIN>__<NORM_KEY>`.
pub fn pin_env_var_name(pin: &PinId, key: &PinKey) -> String {
    format!("PIN_{}__{}", pin.norm(), key.norm())
}

/// Validates a safe Git branch ref short-name (`default_branch` or
/// `GITHUB_BASE_REF`), rejecting empty names, leading `-` option injection,
/// leading/trailing/repeated slashes, `..` traversal, whitespace, and ASCII
/// control characters.
pub fn is_valid_git_branch_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && !name.starts_with('/')
        && !name.ends_with('/')
        && !name.contains("..")
        && !name.contains("//")
        && !name
            .bytes()
            .any(|c| c.is_ascii_control() || c.is_ascii_whitespace())
}

string_id_type!(
    /// Declared check output filename (`^[A-Za-z0-9._-]{1,128}$`, not `.`/`..`).
    OutputName,
    |s: &str| {
        if s.is_empty()
            || s.len() > 128
            || s == "."
            || s == ".."
            || !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(TypeError::InvalidIdentifier {
                kind: "output_name",
                value: s.to_owned(),
            });
        }
        Ok(())
    }
);

/// Fixed 72-character GHCR tag (`{m,i,a,k}sha256-<64-lower-hex>`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LookupTag(String);

impl LookupTag {
    /// Validates a 72-character `{m,i,a,k}sha256-<64-lower-hex>` tag.
    pub fn new(s: &str) -> Result<Self, TypeError> {
        if s.len() != 72 {
            return Err(TypeError::InvalidLookupTag(s.to_owned()));
        }
        let prefix = &s[..8];
        if !matches!(prefix, "msha256-" | "isha256-" | "asha256-" | "ksha256-") {
            return Err(TypeError::InvalidLookupTag(s.to_owned()));
        }
        Sha256Digest::from_hex(&s[8..]).map_err(|_| TypeError::InvalidLookupTag(s.to_owned()))?;
        Ok(Self(s.to_owned()))
    }

    /// Retention anchor tag `msha256-<manifest_hex>` for an untouched image.
    pub fn image_manifest(manifest: &Sha256Digest) -> Self {
        Self(format!("msha256-{}", manifest.to_hex()))
    }

    /// Claim tag `isha256-<recipe_hex>` for `Claim::Image`.
    pub fn image_claim(recipe: &Sha256Digest) -> Self {
        Self(format!("isha256-{}", recipe.to_hex()))
    }

    /// Claim tag `asha256-<action_hex>` for `Claim::Check`.
    pub fn check_claim(action: &Sha256Digest) -> Self {
        Self(format!("asha256-{}", action.to_hex()))
    }

    /// Claim tag `ksha256-<cache_key_hex>` for `Claim::Cache`.
    pub fn cache_claim(key: &Sha256Digest) -> Self {
        Self(format!("ksha256-{}", key.to_hex()))
    }

    /// Returns the 72-character tag string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LookupTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for LookupTag {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for LookupTag {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

/// Validated reusable workflow URI `<owner>/<repo>/.github/workflows/<file>.y[a]ml`
/// without `@<ref>`, globs, or path traversal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkflowUri(String);

impl WorkflowUri {
    /// Validates `<owner>/<repo>/.github/workflows/<file>.(yml|yaml)`.
    pub fn new(s: &str) -> Result<Self, TypeError> {
        if s.contains('@')
            || s.contains('*')
            || s.contains('?')
            || s.contains('[')
            || s.contains('\0')
        {
            return Err(TypeError::InvalidWorkflowUri(s.to_owned()));
        }
        let Some((repo_part, wf_file)) = s.split_once("/.github/workflows/") else {
            return Err(TypeError::InvalidWorkflowUri(s.to_owned()));
        };
        RepoSlug::new(repo_part).map_err(|_| TypeError::InvalidWorkflowUri(s.to_owned()))?;
        if wf_file.contains('/')
            || wf_file == "."
            || wf_file == ".."
            || !(wf_file.ends_with(".yml") || wf_file.ends_with(".yaml"))
            || !wf_file
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(TypeError::InvalidWorkflowUri(s.to_owned()));
        }
        let stem = wf_file
            .strip_suffix(".yml")
            .or_else(|| wf_file.strip_suffix(".yaml"))
            .unwrap_or_default();
        if stem.is_empty() {
            return Err(TypeError::InvalidWorkflowUri(s.to_owned()));
        }
        Ok(Self(s.to_owned()))
    }

    /// Returns `<owner>/<repo>/.github/workflows/<file>.y[a]ml`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Replaces the workflow filename in the same repository's
    /// `.github/workflows/` directory.
    pub fn with_workflow_file(&self, filename: &str) -> Result<Self, TypeError> {
        let (repo_part, _) = self
            .0
            .split_once("/.github/workflows/")
            .expect("WorkflowUri invariant guarantees /.github/workflows/");
        Self::new(&format!("{repo_part}/.github/workflows/{filename}"))
    }
}

impl fmt::Display for WorkflowUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for WorkflowUri {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for WorkflowUri {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

/// Validated Cargo `Cargo.lock` registry index URL (`registry+https://...` or
/// `sparse+https://...`), statically rejecting `git+`, `http://`, `ssh://`, and
/// `file://` sources.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegistryIndexUrl(String);

impl RegistryIndexUrl {
    /// Default crates.io git index URL recorded in `Cargo.lock`.
    pub const CRATES_IO: &'static str = "registry+https://github.com/rust-lang/crates.io-index";

    /// Validates a `registry+https://...` or `sparse+https://...` index URL.
    pub fn new(s: &str) -> Result<Self, TypeError> {
        let rest = s
            .strip_prefix("registry+https://")
            .or_else(|| s.strip_prefix("sparse+https://"))
            .ok_or_else(|| TypeError::InvalidRegistryIndexUrl(s.to_owned()))?;
        if rest.is_empty()
            || rest.starts_with('/')
            || s.bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(TypeError::InvalidRegistryIndexUrl(s.to_owned()));
        }
        Ok(Self(s.to_owned()))
    }

    /// Returns the exact `Cargo.lock` `source` URL string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Translates `registry+https://...` to `https://...` while keeping
    /// `sparse+https://...` verbatim for `--config registries.<name>.index`.
    pub fn cargo_cli_index_url(&self) -> &str {
        self.0.strip_prefix("registry+").unwrap_or(&self.0)
    }
}

impl fmt::Display for RegistryIndexUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for RegistryIndexUrl {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RegistryIndexUrl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

/// Validated `.github/CODEOWNERS` principal (`@user` or `@org/team`, forbidding
/// email owners and empty tokens).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CodeOwnerPrincipal(String);

impl CodeOwnerPrincipal {
    /// Parses a `@user` or `@org/team` GitHub principal.
    pub fn new(s: &str) -> Result<Self, TypeError> {
        let re =
            Regex::new(r"\A@[A-Za-z0-9-]+(?:/[A-Za-z0-9_.-]+)?\z").expect("static regex is valid");
        if !re.is_match(s) {
            return Err(TypeError::InvalidCodeOwnerPrincipal(s.to_owned()));
        }
        if let Some((_, team)) = s.split_once('/')
            && (team == "." || team == "..")
        {
            return Err(TypeError::InvalidCodeOwnerPrincipal(s.to_owned()));
        }
        Ok(Self(s.to_owned()))
    }

    /// Returns the principal token (`@user` or `@org/team`).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CodeOwnerPrincipal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for CodeOwnerPrincipal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CodeOwnerPrincipal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

/// Unix timestamp in whole seconds since `1970-01-01T00:00:00Z`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct UnixSecs(pub u64);

impl UnixSecs {
    /// Checked saturating subtraction in seconds.
    pub const fn saturating_sub(self, rhs: Self) -> u64 {
        self.0.saturating_sub(rhs.0)
    }

    /// Checked saturating addition in seconds.
    pub const fn saturating_add(self, secs: u64) -> Self {
        Self(self.0.saturating_add(secs))
    }
}

/// Supported Linux OCI target platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Platform {
    /// `linux/amd64` (`x86_64`).
    LinuxAmd64,
    /// `linux/arm64` (`aarch64` / `arm64`).
    LinuxArm64,
}

impl Platform {
    /// Parses `linux/amd64` or `linux/arm64`.
    pub fn new(s: &str) -> Result<Self, TypeError> {
        match s {
            "linux/amd64" => Ok(Self::LinuxAmd64),
            "linux/arm64" => Ok(Self::LinuxArm64),
            _ => Err(TypeError::InvalidPlatform(s.to_owned())),
        }
    }

    /// Returns the OCI platform string.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::LinuxAmd64 => "linux/amd64",
            Self::LinuxArm64 => "linux/arm64",
        }
    }

    /// Verifies that host `uname -m` matches this platform (`0` QEMU fallback).
    pub fn matches_uname_arch(&self, uname_m: &str) -> bool {
        match self {
            Self::LinuxAmd64 => uname_m.trim() == "x86_64",
            Self::LinuxArm64 => matches!(uname_m.trim(), "aarch64" | "arm64"),
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Platform {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Platform {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

/// Hermetic CI sandbox topology (`--native` is unrepresentable in CI types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMode {
    /// Unprivileged read-only Docker container (`--network=none --cap-drop=ALL`).
    Container,
    /// Exported OCI rootfs under outer `bwrap --unshare-all --cap-drop ALL`.
    NestedBwrap,
}

impl SandboxMode {
    /// Canonical lowercase name bound in `ActionDigest`.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Container => "container",
            Self::NestedBwrap => "nested_bwrap",
        }
    }
}

/// Execution mode for `ci-core run-local` (separating CI sandboxes from `--native`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRunMode {
    /// Runs the identical Linux `Container` or `NestedBwrap` sandbox as CI.
    Sandboxed(SandboxMode),
    /// Opt-in unsandboxed host execution (`run-local --native` only).
    NativeUnsandboxed,
}

/// Cache key image-binding scope.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CacheScope {
    /// Binds the resolved single-platform OCI image manifest digest `M`.
    #[default]
    PerImage,
    /// Omits `image_manifest` so source-only caches share across images.
    CrossImage,
}

/// Compile-time embedded Sigstore instance selector.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SigstoreRoot {
    /// Public-good Sigstore (`fulcio.sigstore.dev` + `rekor.sigstore.dev`).
    #[default]
    PublicGood,
    /// GitHub private/internal repository instance (`fulcio.githubapp.com` + TSA).
    GitHub,
}

/// Workflow execution mode derived from `(event, shadow_mode, force_execute_all)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    /// Standard content-addressed reuse and sandboxed execution.
    Enforce,
    /// Kill-switch forcing 100% fresh execution (`R_reuse == ∅`).
    ForceExecuteAll,
    /// `pull_request` shadow bring-up mode (`plan` + `gate` only, `0` shards).
    ShadowPrPlanOnly,
}

/// Deterministic `RunMode` mapping shared across `plan` and `evaluate_gate`.
pub const fn expected_run_mode(
    event: TriggerEvent,
    shadow_mode: bool,
    force_execute_all: bool,
) -> RunMode {
    if force_execute_all {
        RunMode::ForceExecuteAll
    } else if shadow_mode && matches!(event, TriggerEvent::PullRequest) {
        RunMode::ShadowPrPlanOnly
    } else {
        RunMode::Enforce
    }
}

/// Supported GitHub Actions trigger events for `ci.yml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerEvent {
    /// `pull_request` targeting `default_branch`.
    PullRequest,
    /// `merge_group` targeting `refs/heads/gh-readonly-queue/<default_branch>/*`.
    MergeGroup,
    /// `push` targeting `refs/heads/<default_branch>`.
    Push,
}

impl TriggerEvent {
    /// Returns the GitHub `GITHUB_EVENT_NAME` string.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PullRequest => "pull_request",
            Self::MergeGroup => "merge_group",
            Self::Push => "push",
        }
    }
}

/// Keyless Sigstore signer verification policy derived from `checks.toml` `[repo]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerPolicy {
    /// Numeric GitHub repository ID (`.1.15`).
    pub repo_id: u64,
    /// Numeric GitHub repository owner ID (`.1.17`).
    pub owner_id: u64,
    /// Protected default branch name (e.g. `"main"`).
    pub default_branch: String,
    /// Expected Fulcio OIDC issuer (`.1.8`).
    pub oidc_issuer: String,
    /// Embedded Sigstore instance (`PublicGood` or `GitHub`).
    pub sigstore: SigstoreRoot,
    /// Canonical reusable engine workflow URI (`<org>/<repo>/.github/workflows/ci.yml`).
    pub trusted_engine_workflow: WorkflowUri,
    /// Canonical read-only PR reusable workflow URI (`<org>/<repo>/.github/workflows/ci-pr.yml`).
    pub trusted_pr_workflow: WorkflowUri,
    /// Canonical reusable Stage-1 review signal workflow URI.
    pub trusted_review_signal_workflow: WorkflowUri,
    /// Canonical reusable Stage-2 review rerun workflow URI.
    pub trusted_review_rerun_workflow: WorkflowUri,
    /// Allowlisted 40-hex engine commit SHAs (`.1.10`).
    pub trusted_engine_shas: NonEmptyVec<GitOid>,
}

/// Caller authorization topology (`RepoRuleset` default vs. passive `OrgRuleset`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CallerMode {
    /// Repo-admin self-service caller mode across `ghec` and `fpt` repositories.
    RepoRuleset {
        /// Validated caller workflow paths under `.github/workflows/`.
        caller_workflows: NonEmptyVec<RepoRelPath>,
        /// Required status check name (`"{caller_prefix} / gate"`).
        gate_check_name: String,
        /// Expected winning principals in `.github/CODEOWNERS`.
        codeowners: NonEmptyVec<CodeOwnerPrincipal>,
    },
    /// Optional passive compatibility with GHEC Organization Ruleset callers.
    OrgRuleset {
        /// Pinned numeric Organization Ruleset `workflow_id`s.
        required_workflow_ids: NonEmptyVec<u64>,
        /// Optional in-repo `on: push` caller workflow under `.github/workflows/`.
        push_caller_workflow: Option<RepoRelPath>,
        /// Required status check name (`"gate"` or `"{caller_prefix} / gate"`).
        gate_check_name: String,
    },
}

impl CallerMode {
    /// Returns the configured gate check run name.
    pub fn gate_check_name(&self) -> &str {
        match self {
            Self::RepoRuleset {
                gate_check_name, ..
            }
            | Self::OrgRuleset {
                gate_check_name, ..
            } => gate_check_name,
        }
    }

    /// Returns `Some(prefix)` when `gate_check_name` has the form
    /// `"{prefix} / gate"`.
    pub fn caller_prefix(&self) -> Option<&str> {
        self.gate_check_name().strip_suffix(" / gate")
    }
}

/// Complete control-plane trust policy (`signer` + `caller`), excluded from all
/// content-addressed digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlanePolicy {
    /// Sigstore and reusable-workflow SHA allowlist policy.
    pub signer: SignerPolicy,
    /// Caller workflow and `CODEOWNERS` / Org-Ruleset policy.
    pub caller: CallerMode,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawControlPlaneTransition {
    base: ControlPlanePolicy,
    candidate: ControlPlanePolicy,
}

impl TryFrom<RawControlPlaneTransition> for ControlPlaneTransition {
    type Error = TypeError;

    fn try_from(raw: RawControlPlaneTransition) -> Result<Self, Self::Error> {
        if raw.base == raw.candidate {
            return Err(TypeError::TrivialControlPlaneTransition);
        }
        Ok(Self {
            base: raw.base,
            candidate: raw.candidate,
        })
    }
}

impl From<ControlPlaneTransition> for RawControlPlaneTransition {
    fn from(tr: ControlPlaneTransition) -> Self {
        Self {
            base: tr.base,
            candidate: tr.candidate,
        }
    }
}

/// Validated non-trivial control-plane policy transition (`base != candidate`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    try_from = "RawControlPlaneTransition",
    into = "RawControlPlaneTransition"
)]
pub struct ControlPlaneTransition {
    base: ControlPlanePolicy,
    candidate: ControlPlanePolicy,
}

impl ControlPlaneTransition {
    /// Returns `Some(transition)` iff `base != candidate`, or `None` when the
    /// control-plane policy is unchanged.
    pub fn new(base: ControlPlanePolicy, candidate: ControlPlanePolicy) -> Option<Self> {
        if base == candidate {
            None
        } else {
            Some(Self { base, candidate })
        }
    }

    /// Returns `Err` if `base == candidate`.
    pub fn try_new(
        base: ControlPlanePolicy,
        candidate: ControlPlanePolicy,
    ) -> Result<Self, TypeError> {
        Self::new(base, candidate).ok_or(TypeError::TrivialControlPlaneTransition)
    }

    /// Base control-plane policy prior to the transition.
    pub fn base(&self) -> &ControlPlanePolicy {
        &self.base
    }

    /// Candidate control-plane policy introduced by the transition.
    pub fn candidate(&self) -> &ControlPlanePolicy {
        &self.candidate
    }
}

/// Observed entry from GitHub REST API `referenced_workflows[]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferencedWorkflow {
    /// Exact GitHub API `path` string (`<owner>/<repo>/.github/workflows/<f>@<ref>`).
    pub path: String,
    /// Resolved 40-hex commit SHA of the called workflow.
    pub sha: GitOid,
    /// Optional `ref` field (omitted by GitHub on external SHA-pinned calls).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_str: Option<String>,
}

impl ReferencedWorkflow {
    /// Extracts the `<owner>/<repo>/.github/workflows/<file>` prefix before `@`.
    pub fn workflow_uri_prefix(&self) -> Option<&str> {
        self.path.split_once('@').map(|(prefix, _)| prefix)
    }
}

/// Metadata observed from `GET /repos/{owner}/{repo}/actions/runs/{run_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRunMeta {
    /// Repository-relative workflow path (e.g. `".github/workflows/ci.yml"`).
    pub path: String,
    /// Numeric GitHub `workflow_id`.
    pub workflow_id: u64,
    /// `true` iff `workflow_url` ends with `/actions/required_workflows/{id}`.
    pub is_org_required_workflow: bool,
    /// Transitive reusable workflows recorded on the run.
    pub referenced_workflows: Vec<ReferencedWorkflow>,
}

impl WorkflowRunMeta {
    /// Classifies `workflow_url` strictly as `/actions/required_workflows/{id}`
    /// (`Ok(true)`) or `/actions/workflows/{id}` (`Ok(false)`).
    pub fn parse_is_org_required_workflow(
        workflow_url: &str,
        expected_workflow_id: u64,
    ) -> Result<bool, String> {
        let req_suffix = format!("/actions/required_workflows/{expected_workflow_id}");
        let repo_suffix = format!("/actions/workflows/{expected_workflow_id}");
        if workflow_url.ends_with(&req_suffix) {
            Ok(true)
        } else if workflow_url.ends_with(&repo_suffix) {
            Ok(false)
        } else {
            Err(format!(
                "unrecognized workflow_url {workflow_url:?} for workflow_id {expected_workflow_id}"
            ))
        }
    }
}

/// Payload SHA-256 and byte length of a declared check output blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputDigest {
    /// SHA-256 digest of the output file bytes.
    pub sha256: Sha256Digest,
    /// Exact byte size of the output file.
    pub size_bytes: u64,
}

/// Uniform attested claim stored as canonical RFC 8785 JCS JSON in the OCI
/// Artifact `Config` blob and bound by `Layer 0` (`Bundle0_3`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Claim {
    /// Attests that `ImageRecipeDigest` built single-platform OCI manifest `manifest`.
    Image {
        /// Canonical `ImageRecipeDigest`.
        recipe: Sha256Digest,
        /// Untouched single-platform OCI image manifest SHA-256 digest.
        manifest: Sha256Digest,
    },
    /// Attests that `ActionDigest` passed inside the hermetic sandbox.
    Check {
        /// Canonical `ActionDigest`.
        action: Sha256Digest,
        /// Captured declared output digests keyed by `OutputName`.
        outputs: BTreeMap<OutputName, OutputDigest>,
        /// Transitive engine signer SHAs of consumed reused images and hydrated caches.
        provenance_signers: BTreeSet<GitOid>,
    },
    /// Attests a `.tar.zst` archive for a named cache slot at `CacheKeyDigest`.
    Cache {
        /// Canonical `CacheKeyDigest`.
        key: Sha256Digest,
        /// Cache slot identifier.
        slot: CacheSlotId,
        /// SHA-256 digest of the `.tar.zst` archive in `Layer 1`.
        archive: Sha256Digest,
        /// Exact byte size of the `.tar.zst` archive.
        size_bytes: u64,
        /// Transitive engine signer SHAs of consumed reused images and co-mounted caches.
        provenance_signers: BTreeSet<GitOid>,
    },
}

impl Claim {
    /// Deterministic 72-character GHCR lookup tag for this claim.
    pub fn lookup_tag(&self) -> LookupTag {
        match self {
            Self::Image { recipe, .. } => LookupTag::image_claim(recipe),
            Self::Check { action, .. } => LookupTag::check_claim(action),
            Self::Cache { key, .. } => LookupTag::cache_claim(key),
        }
    }

    /// Returns the transitive `provenance_signers` set (`empty` on `Claim::Image`).
    pub fn provenance_signers(&self) -> Option<&BTreeSet<GitOid>> {
        match self {
            Self::Image { .. } => None,
            Self::Check {
                provenance_signers, ..
            }
            | Self::Cache {
                provenance_signers, ..
            } => Some(provenance_signers),
        }
    }
}

/// Proof-carrying offline verification token.
///
/// Fields are private and `Deserialize` is intentionally omitted: the sole
/// constructor is `attest::verify_offline`, making unverified reuse or forged
/// signer provenance unrepresentable outside `ci-core-model`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClaim {
    claim: Claim,
    signing_time: UnixSecs,
    signer_sha: GitOid,
}

impl VerifiedClaim {
    pub(crate) fn new(claim: Claim, signing_time: UnixSecs, signer_sha: GitOid) -> Self {
        Self {
            claim,
            signing_time,
            signer_sha,
        }
    }

    /// Verified `Claim` payload.
    pub fn claim(&self) -> &Claim {
        &self.claim
    }

    /// Authenticated Rekor `integrated_time` or RFC 3161 TSA `gen_time`.
    pub const fn signing_time(&self) -> UnixSecs {
        self.signing_time
    }

    /// Verified Fulcio `.1.10` (`buildSignerDigest`) engine commit SHA.
    pub const fn signer_sha(&self) -> GitOid {
        self.signer_sha
    }
}
