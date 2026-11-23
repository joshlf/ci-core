//! Sole v1 `Registry` implementation (`GhcrRegistry` over OCI Distribution v2),
//! pure-OCI layout verifier (`verify_oci_layout`, Obligation `O6`), and
//! deterministic `InMemoryRegistry` fake for integration testing.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use backon::{BlockingRetryable, ExponentialBuilder};
use base64::Engine as _;
use ci_core_model::store::{
    BlobDescriptor, BlobRef, RawClaimArtifact, Registry, StoreError, StoreTier,
};
use ci_core_model::types::{LookupTag, RepoSlug, Sha256Digest};
use reqwest::StatusCode;
use reqwest::blocking::{Body, Client};
use reqwest::redirect::Policy as RedirectPolicy;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;

const OCI_IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_IMAGE_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const DOCKER_MANIFEST_V2_MEDIA_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";
const CLAIM_CONFIG_MEDIA_TYPE: &str = "application/vnd.ci-core.claim.v1+json";
const SIGSTORE_BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciLayoutFile {
    image_layout_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciDescriptor {
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciIndexDoc {
    schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    media_type: Option<String>,
    manifests: Vec<OciDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciImageManifestDoc {
    schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    media_type: Option<String>,
    config: OciDescriptor,
    layers: Vec<OciDescriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct OciImageConfigBlob {
    #[serde(default)]
    config: Option<OciImageRuntimeConfig>,
}

#[derive(Debug, Deserialize)]
struct OciImageRuntimeConfig {
    #[serde(rename = "Env", default)]
    env: Option<Vec<String>>,
}

/// Verified pure single-platform OCI Image Layout (`Obligation O6`).
#[derive(Debug, Clone)]
pub struct VerifiedOciLayout {
    /// Verified SHA-256 of the single-platform OCI image manifest `M`.
    pub manifest_digest: Sha256Digest,
    /// Verified `manifest.config.digest` (`sha256:<hex>` passed directly to
    /// `docker run` / `docker create` after `docker load`).
    pub verified_config_digest: Sha256Digest,
    /// Raw single-platform image manifest bytes.
    pub raw_manifest_bytes: Vec<u8>,
    /// Manifest media type.
    pub manifest_media_type: String,
    /// Extracted `Config.Env` (`["K=V", ...]`) from the verified config blob.
    pub config_env: Vec<String>,
    /// Verified `(digest, size_bytes)` for config + all unique layer blobs.
    pub content_blobs: Vec<(Sha256Digest, u64)>,
}

fn collect_regular_files_strict(
    root: &Path,
    cur: &Path,
    out: &mut BTreeSet<String>,
) -> Result<(), StoreError> {
    let rd = fs::read_dir(cur).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
    for ent_res in rd {
        let ent = ent_res.map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        let path = ent.path();
        let meta =
            fs::symlink_metadata(&path).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            return Err(StoreError::DigestMismatch(format!(
                "OCI layout contains forbidden symlink `{}`",
                path.display()
            )));
        }
        if ft.is_dir() {
            collect_regular_files_strict(root, &path, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| StoreError::InvalidFormat(e.to_string()))?
                .to_str()
                .ok_or_else(|| StoreError::InvalidFormat("non-UTF-8 OCI layout path".to_owned()))?
                .replace('\\', "/");
            out.insert(rel);
        } else {
            return Err(StoreError::DigestMismatch(format!(
                "OCI layout contains irregular file `{}`",
                path.display()
            )));
        }
    }
    Ok(())
}

fn read_verified_blob_in_layout(
    layout_dir: &Path,
    digest: &Sha256Digest,
    expected_size: Option<u64>,
) -> Result<(Vec<u8>, u64), StoreError> {
    let blob_path = layout_dir
        .join("blobs")
        .join("sha256")
        .join(digest.to_hex());
    let meta = fs::symlink_metadata(&blob_path).map_err(|_| {
        StoreError::DigestMismatch(format!("missing OCI blob `blobs/sha256/{digest}`"))
    })?;
    if !meta.file_type().is_file() {
        return Err(StoreError::DigestMismatch(format!(
            "OCI blob `blobs/sha256/{digest}` is not a regular non-symlink file"
        )));
    }
    let bytes = fs::read(&blob_path).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
    let actual_len = bytes.len() as u64;
    if let Some(exp_sz) = expected_size
        && actual_len != exp_sz
    {
        return Err(StoreError::DigestMismatch(format!(
            "OCI blob `{digest}` size {actual_len} != descriptor size {exp_sz}"
        )));
    }
    let actual_digest = Sha256Digest::hash_bytes(&bytes);
    if &actual_digest != digest {
        return Err(StoreError::DigestMismatch(format!(
            "OCI blob `{digest}` hashed to `{actual_digest}`"
        )));
    }
    Ok((bytes, actual_len))
}

/// Strictly validates a pure single-platform OCI Image Layout directory
/// (`§2.2` + Obligation `O6`):
/// 1. Rejects symlinks, legacy Docker `manifest.json`/`repositories`, and any
///    file outside `{oci-layout, index.json}` plus the exact verified
///    `{expected_manifest, config.digest} ∪ layers[*].digest` blobs.
/// 2. Asserts `sha256(raw_manifest_bytes) == expected_manifest`,
///    `sha256(config_blob) == manifest.config.digest`, and
///    `∀ layer ∈ manifest.layers: sha256(layer_blob) == layer.digest`.
/// 3. Returns `VerifiedOciLayout` including `verified_config_digest` for
///    `sha256:<verified_config_digest>` `<loaded_image_id>` pinning.
pub fn verify_oci_layout(
    layout_dir: &Path,
    expected_manifest: &Sha256Digest,
) -> Result<VerifiedOciLayout, StoreError> {
    let mut actual_files = BTreeSet::new();
    collect_regular_files_strict(layout_dir, layout_dir, &mut actual_files)?;

    if actual_files.contains("manifest.json") || actual_files.contains("repositories") {
        return Err(StoreError::DigestMismatch(
            "hybrid Docker archive (`manifest.json` / `repositories`) is forbidden in pure OCI layout"
                .to_owned(),
        ));
    }

    let oci_layout_bytes = fs::read(layout_dir.join("oci-layout"))
        .map_err(|_| StoreError::DigestMismatch("missing `oci-layout` file".to_owned()))?;
    let oci_layout: OciLayoutFile = serde_json::from_slice(&oci_layout_bytes)
        .map_err(|e| StoreError::InvalidFormat(format!("invalid `oci-layout`: {e}")))?;
    if oci_layout.image_layout_version != "1.0.0" {
        return Err(StoreError::InvalidFormat(format!(
            "unsupported imageLayoutVersion {:?}",
            oci_layout.image_layout_version
        )));
    }

    let index_bytes = fs::read(layout_dir.join("index.json"))
        .map_err(|_| StoreError::DigestMismatch("missing `index.json` file".to_owned()))?;
    let mut current_index: OciIndexDoc = serde_json::from_slice(&index_bytes)
        .map_err(|e| StoreError::InvalidFormat(format!("invalid `index.json`: {e}")))?;

    let mut allowed_files: BTreeSet<String> = BTreeSet::new();
    allowed_files.insert("oci-layout".to_owned());
    allowed_files.insert("index.json".to_owned());

    // Unwrap at most one single-entry nested OCI Image Index if present.
    if current_index.manifests.len() != 1 {
        return Err(StoreError::DigestMismatch(format!(
            "expected single-entry `index.json`, found {} entries",
            current_index.manifests.len()
        )));
    }
    let mut top_desc = current_index.manifests.remove(0);
    if top_desc.media_type == OCI_IMAGE_INDEX_MEDIA_TYPE {
        let idx_digest = Sha256Digest::from_oci_digest(&top_desc.digest)
            .map_err(|e| StoreError::DigestMismatch(e.to_string()))?;
        let (nested_bytes, _) =
            read_verified_blob_in_layout(layout_dir, &idx_digest, Some(top_desc.size))?;
        allowed_files.insert(format!("blobs/sha256/{}", idx_digest.to_hex()));
        let mut nested_idx: OciIndexDoc = serde_json::from_slice(&nested_bytes)
            .map_err(|e| StoreError::InvalidFormat(format!("invalid nested OCI index: {e}")))?;
        if nested_idx.manifests.len() != 1 {
            return Err(StoreError::DigestMismatch(format!(
                "nested OCI Image Index must have strictly 1 manifest, found {}",
                nested_idx.manifests.len()
            )));
        }
        top_desc = nested_idx.manifests.remove(0);
    }

    if !matches!(
        top_desc.media_type.as_str(),
        OCI_IMAGE_MANIFEST_MEDIA_TYPE | DOCKER_MANIFEST_V2_MEDIA_TYPE
    ) {
        return Err(StoreError::DigestMismatch(format!(
            "unsupported image manifest mediaType {:?}",
            top_desc.media_type
        )));
    }

    let desc_manifest_digest = Sha256Digest::from_oci_digest(&top_desc.digest)
        .map_err(|e| StoreError::DigestMismatch(e.to_string()))?;
    if &desc_manifest_digest != expected_manifest {
        return Err(StoreError::DigestMismatch(format!(
            "OCI layout manifest digest `{desc_manifest_digest}` != expected `{expected_manifest}`"
        )));
    }

    let (raw_manifest_bytes, _) =
        read_verified_blob_in_layout(layout_dir, expected_manifest, Some(top_desc.size))?;
    allowed_files.insert(format!("blobs/sha256/{}", expected_manifest.to_hex()));

    let manifest_doc: OciImageManifestDoc = serde_json::from_slice(&raw_manifest_bytes)
        .map_err(|e| StoreError::InvalidFormat(format!("invalid OCI image manifest: {e}")))?;

    let verified_config_digest = Sha256Digest::from_oci_digest(&manifest_doc.config.digest)
        .map_err(|e| StoreError::DigestMismatch(e.to_string()))?;
    let (config_bytes, config_len) = read_verified_blob_in_layout(
        layout_dir,
        &verified_config_digest,
        Some(manifest_doc.config.size),
    )?;
    allowed_files.insert(format!("blobs/sha256/{}", verified_config_digest.to_hex()));

    let cfg_parsed: OciImageConfigBlob = serde_json::from_slice(&config_bytes)
        .map_err(|e| StoreError::InvalidFormat(format!("invalid OCI image config JSON: {e}")))?;
    let config_env = cfg_parsed.config.and_then(|c| c.env).unwrap_or_default();

    let mut content_blobs = Vec::new();
    let mut seen_blobs = BTreeSet::new();
    seen_blobs.insert(verified_config_digest);
    content_blobs.push((verified_config_digest, config_len));

    for layer in &manifest_doc.layers {
        let layer_digest = Sha256Digest::from_oci_digest(&layer.digest)
            .map_err(|e| StoreError::DigestMismatch(e.to_string()))?;
        let (_, layer_len) =
            read_verified_blob_in_layout(layout_dir, &layer_digest, Some(layer.size))?;
        allowed_files.insert(format!("blobs/sha256/{}", layer_digest.to_hex()));
        if seen_blobs.insert(layer_digest) {
            content_blobs.push((layer_digest, layer_len));
        }
    }

    if actual_files != allowed_files {
        let extra: Vec<&String> = actual_files.difference(&allowed_files).collect();
        return Err(StoreError::DigestMismatch(format!(
            "OCI layout contains unverified/unexpected files: {extra:?}"
        )));
    }

    Ok(VerifiedOciLayout {
        manifest_digest: *expected_manifest,
        verified_config_digest,
        raw_manifest_bytes,
        manifest_media_type: top_desc.media_type,
        config_env,
        content_blobs,
    })
}

/// Normalizes a raw `docker save` directory into a pure single-platform OCI
/// Image Layout (`Obligation O6`): strips `manifest.json` and `repositories`,
/// unwraps any nested single-entry OCI Image Index so `index.json` references
/// `M = manifests[0]` directly, prunes unreferenced outer-index blobs, and
/// validates the result with `verify_oci_layout`.
pub fn normalize_docker_save_to_pure_oci(
    layout_dir: &Path,
) -> Result<VerifiedOciLayout, StoreError> {
    for legacy in ["manifest.json", "repositories"] {
        let p = layout_dir.join(legacy);
        if fs::symlink_metadata(&p).is_ok() {
            fs::remove_file(&p).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        }
    }

    let index_path = layout_dir.join("index.json");
    let index_bytes =
        fs::read(&index_path).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
    let mut idx: OciIndexDoc = serde_json::from_slice(&index_bytes)
        .map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
    if idx.manifests.len() != 1 {
        return Err(StoreError::InvalidFormat(format!(
            "expected 1 entry in docker save index.json, found {}",
            idx.manifests.len()
        )));
    }
    let mut entry = idx.manifests.remove(0);
    if entry.media_type == OCI_IMAGE_INDEX_MEDIA_TYPE {
        let outer_digest = Sha256Digest::from_oci_digest(&entry.digest)
            .map_err(|e| StoreError::DigestMismatch(e.to_string()))?;
        let (nested_bytes, _) =
            read_verified_blob_in_layout(layout_dir, &outer_digest, Some(entry.size))?;
        let mut nested: OciIndexDoc = serde_json::from_slice(&nested_bytes)
            .map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        if nested.manifests.len() != 1 {
            return Err(StoreError::InvalidFormat(format!(
                "expected 1 platform manifest inside OCI index, found {}",
                nested.manifests.len()
            )));
        }
        entry = nested.manifests.remove(0);
        // Remove the outer index blob so only the single-platform manifest,
        // config, and layers remain.
        let outer_blob_path = layout_dir
            .join("blobs")
            .join("sha256")
            .join(outer_digest.to_hex());
        let _ = fs::remove_file(outer_blob_path);
        let rewritten = OciIndexDoc {
            schema_version: 2,
            media_type: Some(OCI_IMAGE_INDEX_MEDIA_TYPE.to_owned()),
            manifests: vec![OciDescriptor {
                media_type: entry.media_type.clone(),
                digest: entry.digest.clone(),
                size: entry.size,
                annotations: BTreeMap::new(),
            }],
        };
        let rewritten_bytes =
            serde_json::to_vec(&rewritten).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        fs::write(&index_path, rewritten_bytes)
            .map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
    }

    let expected_m = Sha256Digest::from_oci_digest(&entry.digest)
        .map_err(|e| StoreError::DigestMismatch(e.to_string()))?;
    verify_oci_layout(layout_dir, &expected_m)
}

/// Computes `(sha256, size_bytes)` of a local file before uploading.
pub fn hash_local_file(path: &Path) -> Result<(Sha256Digest, u64), StoreError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| StoreError::InvalidFormat(format!("{}: {e}", path.display())))?;
    if !meta.file_type().is_file() {
        return Err(StoreError::DigestMismatch(format!(
            "`{}` is not a regular non-symlink file",
            path.display()
        )));
    }
    let mut f = File::open(path)
        .map_err(|e| StoreError::InvalidFormat(format!("{}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buf = [0u8; 65_536];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Ok((Sha256Digest::from_bytes(out), total))
}

#[derive(Deserialize)]
struct GhcrTokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

fn oci_retry_policy() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(250))
        .with_max_delay(Duration::from_secs(4))
        .with_max_times(3)
        .with_jitter()
}

/// Parses an RFC 7235 `WWW-Authenticate: Bearer realm="...",service="..."`
/// challenge header into `(realm, Option<service>)`.
pub fn parse_bearer_www_authenticate(header: &str) -> Option<(String, Option<String>)> {
    let trimmed = header.trim();
    let params_str = trimmed
        .strip_prefix("Bearer ")
        .or_else(|| trimmed.strip_prefix("bearer "))?;
    let mut realm = None;
    let mut service = None;
    let mut rest = params_str.trim();
    while !rest.is_empty() {
        let (key, after_eq) = rest.split_once('=')?;
        let key = key.trim();
        let after_eq = after_eq.trim_start();
        let (val, remainder) = if let Some(quoted) = after_eq.strip_prefix('"') {
            let mut end = None;
            let mut esc = false;
            for (i, ch) in quoted.char_indices() {
                if esc {
                    esc = false;
                    continue;
                }
                if ch == '\\' {
                    esc = true;
                    continue;
                }
                if ch == '"' {
                    end = Some(i);
                    break;
                }
            }
            let end_idx = end?;
            let v = &quoted[..end_idx];
            let rem = quoted[end_idx + 1..].trim_start();
            let rem = rem.strip_prefix(',').unwrap_or(rem).trim_start();
            (v.to_owned(), rem)
        } else {
            match after_eq.split_once(',') {
                Some((v, rem)) => (v.trim().to_owned(), rem.trim_start()),
                None => (after_eq.trim().to_owned(), ""),
            }
        };
        if key.eq_ignore_ascii_case("realm") {
            realm = Some(val);
        } else if key.eq_ignore_ascii_case("service") {
            service = Some(val);
        }
        rest = remainder;
    }
    Some((realm?, service))
}

fn resolve_oci_location(host: &str, base_url_str: &str, loc: &str) -> Result<Url, StoreError> {
    let base = Url::parse(base_url_str)
        .or_else(|_| Url::parse(&format!("https://{host}/")))
        .map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
    base.join(loc)
        .map_err(|e| StoreError::InvalidFormat(format!("invalid Location {loc:?}: {e}")))
}

/// Native OCI Distribution v2 client targeting GitHub Container Registry
/// (`ghcr.io`) and standard Bearer-authenticated OCI v2 registries.
pub struct GhcrRegistry {
    api_client: Client,
    redirect_no_auth_client: Client,
    cas_host_and_repo: (String, String),
    cache_host_and_repo: (String, String),
    source_repo_url: String,
    bearer_credential: Option<String>,
    token_cache: Mutex<BTreeMap<(String, String), String>>,
    realm_cache: Mutex<BTreeMap<String, (String, Option<String>)>>,
    uploaded_bundles: Mutex<BTreeSet<(StoreTier, Sha256Digest)>>,
}

impl GhcrRegistry {
    /// Constructs a `GhcrRegistry` from `checks.toml` `[repo]` settings and an
    /// optional token (`GITHUB_TOKEN` in CI or `CI_CORE_GHCR_TOKEN` locally).
    pub fn new(
        slug: &RepoSlug,
        cas_repo_uri: &str,
        cache_repo_uri: &str,
        bearer_credential: Option<String>,
    ) -> Result<Self, StoreError> {
        let api_client = Client::builder()
            .redirect(RedirectPolicy::none())
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| StoreError::Transient(e.to_string()))?;
        let redirect_no_auth_client = Client::builder()
            .redirect(RedirectPolicy::limited(5))
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(|e| StoreError::Transient(e.to_string()))?;

        Ok(Self {
            api_client,
            redirect_no_auth_client,
            cas_host_and_repo: Self::split_registry_uri(cas_repo_uri)?,
            cache_host_and_repo: Self::split_registry_uri(cache_repo_uri)?,
            source_repo_url: slug.source_repo_url(),
            bearer_credential: bearer_credential.filter(|t| !t.trim().is_empty()),
            token_cache: Mutex::new(BTreeMap::new()),
            realm_cache: Mutex::new(BTreeMap::new()),
            uploaded_bundles: Mutex::new(BTreeSet::new()),
        })
    }

    fn split_registry_uri(uri: &str) -> Result<(String, String), StoreError> {
        let trimmed = uri
            .strip_prefix("https://")
            .or_else(|| uri.strip_prefix("oci://"))
            .unwrap_or(uri);
        let Some((host, repo_path)) = trimmed.split_once('/') else {
            return Err(StoreError::InvalidFormat(format!(
                "invalid OCI repository URI {uri:?}"
            )));
        };
        if host.is_empty() || repo_path.is_empty() {
            return Err(StoreError::InvalidFormat(format!(
                "invalid OCI repository URI {uri:?}"
            )));
        }
        Ok((host.to_ascii_lowercase(), repo_path.to_ascii_lowercase()))
    }

    fn tier_coords(&self, tier: StoreTier) -> (&str, &str) {
        match tier {
            StoreTier::PublicCas => (&self.cas_host_and_repo.0, &self.cas_host_and_repo.1),
            StoreTier::PrivateCache => (&self.cache_host_and_repo.0, &self.cache_host_and_repo.1),
        }
    }

    fn resolve_token_endpoint(&self, host: &str) -> Result<(String, Option<String>), StoreError> {
        if host == "ghcr.io" {
            return Ok((format!("https://{host}/token"), Some(host.to_owned())));
        }
        if let Some(cached) = self.realm_cache.lock().expect("mutex").get(host).cloned() {
            return Ok(cached);
        }
        let v2_url = format!("https://{host}/v2/");
        let resp = (|| {
            self.api_client
                .get(&v2_url)
                .send()
                .map_err(|e| StoreError::Transient(e.to_string()))
        })
        .retry(oci_retry_policy())
        .when(|e| matches!(e, StoreError::Transient(_)))
        .call()?;
        let parsed = resp
            .headers()
            .get("www-authenticate")
            .and_then(|h| h.to_str().ok())
            .and_then(parse_bearer_www_authenticate)
            .unwrap_or_else(|| (format!("https://{host}/token"), Some(host.to_owned())));
        self.realm_cache
            .lock()
            .expect("mutex")
            .insert(host.to_owned(), parsed.clone());
        Ok(parsed)
    }

    fn fetch_registry_jwt(
        &self,
        host: &str,
        repo: &str,
        scope_actions: &str,
        use_auth: bool,
    ) -> Result<Option<String>, StoreError> {
        let key = (
            format!("{host}/{repo}"),
            format!("{scope_actions}:auth={use_auth}"),
        );
        if let Some(tok) = self.token_cache.lock().expect("mutex").get(&key).cloned() {
            return Ok(Some(tok));
        }
        if use_auth && self.bearer_credential.is_none() {
            return Ok(None);
        }

        let (realm, service_opt) = self.resolve_token_endpoint(host)?;
        let mut tok_url = Url::parse(&realm).map_err(|e| {
            StoreError::InvalidFormat(format!("invalid token realm {realm:?}: {e}"))
        })?;
        {
            let mut qp = tok_url.query_pairs_mut();
            if let Some(ref svc) = service_opt {
                qp.append_pair("service", svc);
            }
            qp.append_pair("scope", &format!("repository:{repo}:{scope_actions}"));
        }

        let token_opt = (|| -> Result<Option<String>, StoreError> {
            let mut req = self.api_client.get(tok_url.clone());
            if use_auth && let Some(ref cred) = self.bearer_credential {
                let basic = base64::engine::general_purpose::STANDARD
                    .encode(format!("x-access-token:{cred}"));
                req = req.header("Authorization", format!("Basic {basic}"));
            }
            let resp = req
                .send()
                .map_err(|e| StoreError::Transient(e.to_string()))?;
            let status = resp.status();
            if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
                return Ok(None);
            }
            if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
                return Err(StoreError::Transient(format!(
                    "token endpoint returned HTTP {status}"
                )));
            }
            if !status.is_success() {
                return Ok(None);
            }
            let body: GhcrTokenResponse = resp
                .json()
                .map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
            Ok(body.token.or(body.access_token))
        })
        .retry(oci_retry_policy())
        .when(|e| matches!(e, StoreError::Transient(_)))
        .call()?;

        if let Some(ref tok) = token_opt {
            self.token_cache
                .lock()
                .expect("mutex")
                .insert(key, tok.clone());
        }
        Ok(token_opt)
    }

    fn pull_token(&self, tier: StoreTier) -> Result<Option<String>, StoreError> {
        let (host, repo) = self.tier_coords(tier);
        if self.bearer_credential.is_some()
            && let Some(tok) = self.fetch_registry_jwt(host, repo, "pull", true)?
        {
            return Ok(Some(tok));
        }
        // Anonymous fallback on public `PublicCas` (and opt-in public caches)
        // when unset or when a fork `GITHUB_TOKEN` receives `401`/`403`.
        self.fetch_registry_jwt(host, repo, "pull", false)
    }

    fn push_token(&self, tier: StoreTier) -> Result<String, StoreError> {
        let (host, repo) = self.tier_coords(tier);
        self.fetch_registry_jwt(host, repo, "pull,push", true)?
            .ok_or_else(|| {
                StoreError::Unauthorized(format!("failed to obtain push token for {host}/{repo}"))
            })
    }

    fn get_manifest_raw(
        &self,
        tier: StoreTier,
        reference: &str,
    ) -> Result<Option<(Vec<u8>, String)>, StoreError> {
        let (host, repo) = self.tier_coords(tier);
        let url = format!("https://{host}/v2/{repo}/manifests/{reference}");
        let accept = format!(
            "{OCI_IMAGE_MANIFEST_MEDIA_TYPE}, {DOCKER_MANIFEST_V2_MEDIA_TYPE}, {OCI_IMAGE_INDEX_MEDIA_TYPE}"
        );
        let tok = self.pull_token(tier)?;

        (|| -> Result<Option<(Vec<u8>, String)>, StoreError> {
            let try_once =
                |token_opt: Option<&str>| -> Result<reqwest::blocking::Response, StoreError> {
                    let mut req = self.api_client.get(&url).header("Accept", &accept);
                    if let Some(t) = token_opt {
                        req = req.header("Authorization", format!("Bearer {t}"));
                    }
                    req.send().map_err(|e| StoreError::Transient(e.to_string()))
                };

            let mut resp = try_once(tok.as_deref())?;
            if matches!(
                resp.status(),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            ) && self.bearer_credential.is_some()
                && let Some(anon_tok) = self.fetch_registry_jwt(host, repo, "pull", false)?
            {
                resp = try_once(Some(&anon_tok))?;
            }

            let status = resp.status();
            if status == StatusCode::NOT_FOUND
                || status == StatusCode::UNAUTHORIZED
                || status == StatusCode::FORBIDDEN
            {
                // Read-only discovery/hydration `401`/`403` degrades uniformly to miss.
                return Ok(None);
            }
            if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
                return Err(StoreError::Transient(format!(
                    "GET manifest `{reference}` returned HTTP {status}"
                )));
            }
            if !status.is_success() {
                return Err(StoreError::InvalidFormat(format!(
                    "GET manifest `{reference}` returned HTTP {status}"
                )));
            }
            let ct = resp
                .headers()
                .get("content-type")
                .and_then(|h| h.to_str().ok())
                .unwrap_or(OCI_IMAGE_MANIFEST_MEDIA_TYPE)
                .split(';')
                .next()
                .unwrap_or(OCI_IMAGE_MANIFEST_MEDIA_TYPE)
                .trim()
                .to_owned();
            let bytes = resp
                .bytes()
                .map_err(|e| StoreError::Transient(e.to_string()))?
                .to_vec();
            Ok(Some((bytes, ct)))
        })
        .retry(oci_retry_policy())
        .when(|e| matches!(e, StoreError::Transient(_)))
        .call()
    }

    fn download_blob_to_vec(
        &self,
        tier: StoreTier,
        digest: &Sha256Digest,
        max_bytes: u64,
    ) -> Result<Vec<u8>, StoreError> {
        let tmp =
            tempfile::NamedTempFile::new().map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        self.fetch_blob_verified(tier, digest, tmp.path(), max_bytes)?;
        fs::read(tmp.path()).map_err(|e| StoreError::InvalidFormat(e.to_string()))
    }

    fn ensure_blob_uploaded_source<F>(
        &self,
        tier: StoreTier,
        digest: &Sha256Digest,
        expected_size: u64,
        open_body: F,
    ) -> Result<(), StoreError>
    where
        F: Fn() -> Result<Body, StoreError>,
    {
        let (host, repo) = self.tier_coords(tier);
        let tok = self.push_token(tier)?;
        let head_url = format!("https://{host}/v2/{repo}/blobs/sha256:{}", digest.to_hex());
        let start_url = format!("https://{host}/v2/{repo}/blobs/uploads/");

        (|| -> Result<(), StoreError> {
            let head_resp = self
                .api_client
                .head(&head_url)
                .header("Authorization", format!("Bearer {tok}"))
                .send()
                .map_err(|e| StoreError::Transient(e.to_string()))?;
            if head_resp.status().is_success() {
                return Ok(());
            }

            let post_resp = self
                .api_client
                .post(&start_url)
                .header("Authorization", format!("Bearer {tok}"))
                .header("Content-Length", "0")
                .send()
                .map_err(|e| StoreError::Transient(e.to_string()))?;
            if !post_resp.status().is_success() && post_resp.status() != StatusCode::ACCEPTED {
                return Err(StoreError::Transient(format!(
                    "POST blobs/uploads returned HTTP {}",
                    post_resp.status()
                )));
            }
            let loc = post_resp
                .headers()
                .get("location")
                .and_then(|h| h.to_str().ok())
                .ok_or_else(|| {
                    StoreError::InvalidFormat("missing upload Location header".to_owned())
                })?;
            let mut put_url = resolve_oci_location(host, &start_url, loc)?;
            put_url
                .query_pairs_mut()
                .append_pair("digest", &digest.to_oci_digest());

            let body = open_body()?;
            let put_resp = self
                .api_client
                .put(put_url)
                .header("Authorization", format!("Bearer {tok}"))
                .header("Content-Type", "application/octet-stream")
                .header("Content-Length", expected_size.to_string())
                .body(body)
                .send()
                .map_err(|e| StoreError::Transient(e.to_string()))?;
            let st = put_resp.status();
            if st.is_server_error() || st == StatusCode::TOO_MANY_REQUESTS {
                return Err(StoreError::Transient(format!(
                    "PUT blob upload returned HTTP {st}"
                )));
            }
            if !st.is_success() {
                return Err(StoreError::Unauthorized(format!(
                    "PUT blob upload failed with HTTP {st}"
                )));
            }
            Ok(())
        })
        .retry(oci_retry_policy())
        .when(|e| matches!(e, StoreError::Transient(_)))
        .call()
    }

    fn ensure_blob_uploaded_bytes(
        &self,
        tier: StoreTier,
        digest: &Sha256Digest,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        let actual = Sha256Digest::hash_bytes(bytes);
        if &actual != digest {
            return Err(StoreError::DigestMismatch(format!(
                "in-memory blob hash `{actual}` != expected `{digest}`"
            )));
        }
        self.ensure_blob_uploaded_source(tier, digest, bytes.len() as u64, || {
            Ok(Body::from(bytes.to_vec()))
        })
    }

    fn put_manifest_raw(
        &self,
        tier: StoreTier,
        reference: &str,
        media_type: &str,
        manifest_bytes: &[u8],
    ) -> Result<(), StoreError> {
        let (host, repo) = self.tier_coords(tier);
        let tok = self.push_token(tier)?;
        let url = format!("https://{host}/v2/{repo}/manifests/{reference}");
        (|| -> Result<(), StoreError> {
            let resp = self
                .api_client
                .put(&url)
                .header("Authorization", format!("Bearer {tok}"))
                .header("Content-Type", media_type)
                .body(manifest_bytes.to_vec())
                .send()
                .map_err(|e| StoreError::Transient(e.to_string()))?;
            let st = resp.status();
            if st.is_server_error() || st == StatusCode::TOO_MANY_REQUESTS {
                return Err(StoreError::Transient(format!(
                    "PUT manifest `{reference}` returned HTTP {st}"
                )));
            }
            if matches!(st, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
                return Err(StoreError::Unauthorized(format!(
                    "PUT manifest `{reference}` unauthorized (HTTP {st})"
                )));
            }
            if !st.is_success() {
                return Err(StoreError::InvalidFormat(format!(
                    "PUT manifest `{reference}` failed with HTTP {st}"
                )));
            }
            Ok(())
        })
        .retry(oci_retry_policy())
        .when(|e| matches!(e, StoreError::Transient(_)))
        .call()
    }
}

impl Registry for GhcrRegistry {
    fn fetch_claim_artifact(
        &self,
        tier: StoreTier,
        tag: &LookupTag,
    ) -> Result<Option<RawClaimArtifact>, StoreError> {
        let Some((manifest_bytes, _)) = self.get_manifest_raw(tier, tag.as_str())? else {
            return Ok(None);
        };
        let doc: OciImageManifestDoc = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| StoreError::InvalidFormat(format!("claim manifest JSON: {e}")))?;
        if doc.layers.is_empty() {
            return Err(StoreError::InvalidFormat(
                "claim manifest missing Layer 0 bundle".to_owned(),
            ));
        }
        let cfg_digest = Sha256Digest::from_oci_digest(&doc.config.digest)
            .map_err(|e| StoreError::DigestMismatch(e.to_string()))?;
        let claim_bytes = self.download_blob_to_vec(tier, &cfg_digest, 1_048_576)?;
        let bundle_digest = Sha256Digest::from_oci_digest(&doc.layers[0].digest)
            .map_err(|e| StoreError::DigestMismatch(e.to_string()))?;
        let bundle_bytes = self.download_blob_to_vec(tier, &bundle_digest, 4_194_304)?;

        let mut payload_layers = Vec::with_capacity(doc.layers.len().saturating_sub(1));
        for l in &doc.layers[1..] {
            let ldig = Sha256Digest::from_oci_digest(&l.digest)
                .map_err(|e| StoreError::DigestMismatch(e.to_string()))?;
            payload_layers.push(BlobDescriptor {
                digest: ldig,
                size_bytes: l.size,
                media_type: l.media_type.clone(),
                title: l.annotations.get("org.opencontainers.image.title").cloned(),
            });
        }
        Ok(Some(RawClaimArtifact {
            claim_bytes,
            bundle_bytes,
            payload_layers,
        }))
    }

    fn head_oci_manifest_by_digest(
        &self,
        tier: StoreTier,
        digest: &Sha256Digest,
    ) -> Result<bool, StoreError> {
        let Some((raw_bytes, _)) = self.get_manifest_raw(tier, &digest.to_oci_digest())? else {
            return Ok(false);
        };
        Ok(&Sha256Digest::hash_bytes(&raw_bytes) == digest)
    }

    fn fetch_oci_image_by_digest(
        &self,
        tier: StoreTier,
        digest: &Sha256Digest,
        dest_layout_dir: &Path,
    ) -> Result<Sha256Digest, StoreError> {
        let Some((raw_manifest_bytes, media_type)) =
            self.get_manifest_raw(tier, &digest.to_oci_digest())?
        else {
            return Err(StoreError::NotFound(format!(
                "OCI image manifest `{digest}` not found"
            )));
        };
        let actual_m = Sha256Digest::hash_bytes(&raw_manifest_bytes);
        if &actual_m != digest {
            return Err(StoreError::DigestMismatch(format!(
                "pulled manifest hashed to `{actual_m}` != `{digest}`"
            )));
        }

        let blobs_dir = dest_layout_dir.join("blobs").join("sha256");
        fs::create_dir_all(&blobs_dir).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        fs::write(
            dest_layout_dir.join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .map_err(|e| StoreError::InvalidFormat(e.to_string()))?;

        let idx = OciIndexDoc {
            schema_version: 2,
            media_type: Some(OCI_IMAGE_INDEX_MEDIA_TYPE.to_owned()),
            manifests: vec![OciDescriptor {
                media_type,
                digest: digest.to_oci_digest(),
                size: raw_manifest_bytes.len() as u64,
                annotations: BTreeMap::new(),
            }],
        };
        fs::write(
            dest_layout_dir.join("index.json"),
            serde_json::to_vec(&idx).map_err(|e| StoreError::InvalidFormat(e.to_string()))?,
        )
        .map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        fs::write(blobs_dir.join(digest.to_hex()), &raw_manifest_bytes)
            .map_err(|e| StoreError::InvalidFormat(e.to_string()))?;

        let mdoc: OciImageManifestDoc = serde_json::from_slice(&raw_manifest_bytes)
            .map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        let cfg_dig = Sha256Digest::from_oci_digest(&mdoc.config.digest)
            .map_err(|e| StoreError::DigestMismatch(e.to_string()))?;
        self.fetch_blob_verified(
            tier,
            &cfg_dig,
            &blobs_dir.join(cfg_dig.to_hex()),
            mdoc.config.size,
        )?;
        for layer in &mdoc.layers {
            let ldig = Sha256Digest::from_oci_digest(&layer.digest)
                .map_err(|e| StoreError::DigestMismatch(e.to_string()))?;
            let dst = blobs_dir.join(ldig.to_hex());
            if !dst.exists() {
                self.fetch_blob_verified(tier, &ldig, &dst, layer.size)?;
            }
        }

        let verified = verify_oci_layout(dest_layout_dir, digest)?;
        Ok(verified.verified_config_digest)
    }

    fn fetch_blob_verified(
        &self,
        tier: StoreTier,
        digest: &Sha256Digest,
        dest: &Path,
        max_bytes: u64,
    ) -> Result<u64, StoreError> {
        let (host, repo) = self.tier_coords(tier);
        let url = format!("https://{host}/v2/{repo}/blobs/sha256:{}", digest.to_hex());
        let tok = self.pull_token(tier)?;

        (|| -> Result<u64, StoreError> {
            let mut req = self.api_client.get(&url);
            if let Some(ref t) = tok {
                req = req.header("Authorization", format!("Bearer {t}"));
            }
            let mut resp = req
                .send()
                .map_err(|e| StoreError::Transient(e.to_string()))?;

            // Never forward `Authorization` across `307` CDN blob redirects.
            if resp.status().is_redirection() {
                let loc = resp
                    .headers()
                    .get("location")
                    .and_then(|h| h.to_str().ok())
                    .ok_or_else(|| StoreError::InvalidFormat("307 without Location".to_owned()))?
                    .to_owned();
                let resolved = resolve_oci_location(host, &url, &loc)?;
                resp = self
                    .redirect_no_auth_client
                    .get(resolved)
                    .send()
                    .map_err(|e| StoreError::Transient(e.to_string()))?;
            }

            let st = resp.status();
            if st == StatusCode::NOT_FOUND {
                return Err(StoreError::NotFound(format!("blob `{digest}` not found")));
            }
            if matches!(st, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
                return Err(StoreError::Unauthorized(format!(
                    "blob `{digest}` unauthorized (HTTP {st})"
                )));
            }
            if st.is_server_error() || st == StatusCode::TOO_MANY_REQUESTS {
                return Err(StoreError::Transient(format!(
                    "blob `{digest}` returned HTTP {st}"
                )));
            }
            if !st.is_success() {
                return Err(StoreError::InvalidFormat(format!(
                    "blob `{digest}` failed with HTTP {st}"
                )));
            }

            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
            }
            let tmp_dest = dest.with_extension("part");
            let mut out_file =
                File::create(&tmp_dest).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
            let mut hasher = Sha256::new();
            let mut total = 0u64;
            let mut buf = [0u8; 65_536];
            loop {
                let n = resp.read(&mut buf).map_err(|e| {
                    let _ = fs::remove_file(&tmp_dest);
                    StoreError::Transient(e.to_string())
                })?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                if total > max_bytes {
                    let _ = fs::remove_file(&tmp_dest);
                    return Err(StoreError::DigestMismatch(format!(
                        "blob `{digest}` exceeded max_bytes {max_bytes}"
                    )));
                }
                hasher.update(&buf[..n]);
                out_file.write_all(&buf[..n]).map_err(|e| {
                    let _ = fs::remove_file(&tmp_dest);
                    StoreError::InvalidFormat(e.to_string())
                })?;
            }
            out_file
                .sync_all()
                .map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
            drop(out_file);

            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hasher.finalize());
            let actual = Sha256Digest::from_bytes(arr);
            if &actual != digest {
                let _ = fs::remove_file(&tmp_dest);
                return Err(StoreError::DigestMismatch(format!(
                    "downloaded blob hashed to `{actual}` != `{digest}`"
                )));
            }
            fs::rename(&tmp_dest, dest).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
            Ok(total)
        })
        .retry(oci_retry_policy())
        .when(|e| matches!(e, StoreError::Transient(_)))
        .call()
    }

    fn push_untouched_oci_layout(
        &self,
        tier: StoreTier,
        layout_dir: &Path,
        expected_manifest: &Sha256Digest,
        anchor_tag: &LookupTag,
    ) -> Result<(), StoreError> {
        let verified = verify_oci_layout(layout_dir, expected_manifest)?;
        for (blob_dig, expected_sz) in &verified.content_blobs {
            let blob_path = layout_dir
                .join("blobs")
                .join("sha256")
                .join(blob_dig.to_hex());
            self.upload_verified_blob(tier, &blob_path, blob_dig, *expected_sz)?;
        }
        self.put_manifest_raw(
            tier,
            anchor_tag.as_str(),
            &verified.manifest_media_type,
            &verified.raw_manifest_bytes,
        )
    }

    fn upload_verified_blob(
        &self,
        tier: StoreTier,
        path: &Path,
        expected_digest: &Sha256Digest,
        expected_size: u64,
    ) -> Result<(), StoreError> {
        let (actual_digest, actual_size) = hash_local_file(path)?;
        if &actual_digest != expected_digest || actual_size != expected_size {
            return Err(StoreError::DigestMismatch(format!(
                "local blob `{}` ({actual_digest}, {actual_size}B) != expected ({expected_digest}, {expected_size}B)",
                path.display()
            )));
        }
        // Stream directly from disk via `Body::sized(file, expected_size)` so
        // multi-GiB OCI image layers use O(1) memory rather than buffering in RAM.
        self.ensure_blob_uploaded_source(tier, expected_digest, expected_size, || {
            let f = File::open(path).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
            Ok(Body::sized(f, expected_size))
        })
    }

    fn put_claim_artifact(
        &self,
        tier: StoreTier,
        tag: &LookupTag,
        claim_bytes: &[u8],
        bundle_blob: &BlobRef,
        payload_blobs: &[BlobDescriptor],
    ) -> Result<(), StoreError> {
        let claim_digest = Sha256Digest::hash_bytes(claim_bytes);
        self.ensure_blob_uploaded_bytes(tier, &claim_digest, claim_bytes)?;

        // Deduplicate `Layer 0` (`Bundle0_3`) uploads per `(tier, bundle.digest)`.
        let already_up = self
            .uploaded_bundles
            .lock()
            .expect("mutex")
            .contains(&(tier, bundle_blob.digest));
        if !already_up {
            self.ensure_blob_uploaded_bytes(tier, &bundle_blob.digest, &bundle_blob.bytes)?;
            self.uploaded_bundles
                .lock()
                .expect("mutex")
                .insert((tier, bundle_blob.digest));
        }

        let mut layers = Vec::with_capacity(1 + payload_blobs.len());
        layers.push(OciDescriptor {
            media_type: SIGSTORE_BUNDLE_MEDIA_TYPE.to_owned(),
            digest: bundle_blob.digest.to_oci_digest(),
            size: bundle_blob.bytes.len() as u64,
            annotations: BTreeMap::new(),
        });
        for pb in payload_blobs {
            let mut ann = BTreeMap::new();
            if let Some(ref title) = pb.title {
                ann.insert("org.opencontainers.image.title".to_owned(), title.clone());
            }
            layers.push(OciDescriptor {
                media_type: pb.media_type.clone(),
                digest: pb.digest.to_oci_digest(),
                size: pb.size_bytes,
                annotations: ann,
            });
        }

        let mut manifest_ann = BTreeMap::new();
        manifest_ann.insert(
            "org.opencontainers.image.source".to_owned(),
            self.source_repo_url.clone(),
        );
        let manifest = OciImageManifestDoc {
            schema_version: 2,
            media_type: Some(OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_owned()),
            config: OciDescriptor {
                media_type: CLAIM_CONFIG_MEDIA_TYPE.to_owned(),
                digest: claim_digest.to_oci_digest(),
                size: claim_bytes.len() as u64,
                annotations: BTreeMap::new(),
            },
            layers,
            annotations: manifest_ann,
        };
        let manifest_bytes =
            serde_json::to_vec(&manifest).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        self.put_manifest_raw(
            tier,
            tag.as_str(),
            OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            &manifest_bytes,
        )
    }
}

/// High-fidelity in-memory `Registry` fake enforcing identical local digest and
/// `verify_oci_layout` checks and recording commit order (`tag` push history).
#[derive(Debug, Default)]
pub struct InMemoryRegistry {
    state: Mutex<InMemoryRegistryState>,
    forbid_private_cache_reads: bool,
    forbid_public_cas_reads: bool,
}

#[derive(Debug, Default)]
struct InMemoryRegistryState {
    blobs: BTreeMap<(StoreTier, Sha256Digest), Vec<u8>>,
    image_layouts: BTreeMap<(StoreTier, Sha256Digest), PathBuf>,
    claims: BTreeMap<(StoreTier, LookupTag), RawClaimArtifact>,
    committed_tags_order: Vec<(StoreTier, LookupTag)>,
    bundle_upload_count: BTreeMap<(StoreTier, Sha256Digest), usize>,
}

impl InMemoryRegistry {
    /// Creates an empty `InMemoryRegistry`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulates HTTP `401`/`403` on read-only discovery (`401/403 -> miss`).
    pub fn with_read_denial(mut self, deny_public_cas: bool, deny_private_cache: bool) -> Self {
        self.forbid_public_cas_reads = deny_public_cas;
        self.forbid_private_cache_reads = deny_private_cache;
        self
    }

    /// Returns the exact chronological `(StoreTier, LookupTag)` commit sequence.
    pub fn committed_tags_order(&self) -> Vec<(StoreTier, LookupTag)> {
        self.state
            .lock()
            .expect("mutex")
            .committed_tags_order
            .clone()
    }

    /// Returns how many times `(tier, bundle_digest)` was uploaded.
    pub fn bundle_upload_count(&self, tier: StoreTier, bundle_digest: &Sha256Digest) -> usize {
        self.state
            .lock()
            .expect("mutex")
            .bundle_upload_count
            .get(&(tier, *bundle_digest))
            .copied()
            .unwrap_or(0)
    }

    fn is_read_denied(&self, tier: StoreTier) -> bool {
        match tier {
            StoreTier::PublicCas => self.forbid_public_cas_reads,
            StoreTier::PrivateCache => self.forbid_private_cache_reads,
        }
    }
}

impl Registry for InMemoryRegistry {
    fn fetch_claim_artifact(
        &self,
        tier: StoreTier,
        tag: &LookupTag,
    ) -> Result<Option<RawClaimArtifact>, StoreError> {
        if self.is_read_denied(tier) {
            return Ok(None);
        }
        Ok(self
            .state
            .lock()
            .expect("mutex")
            .claims
            .get(&(tier, tag.clone()))
            .cloned())
    }

    fn head_oci_manifest_by_digest(
        &self,
        tier: StoreTier,
        digest: &Sha256Digest,
    ) -> Result<bool, StoreError> {
        if self.is_read_denied(tier) {
            return Ok(false);
        }
        Ok(self
            .state
            .lock()
            .expect("mutex")
            .image_layouts
            .contains_key(&(tier, *digest)))
    }

    fn fetch_oci_image_by_digest(
        &self,
        tier: StoreTier,
        digest: &Sha256Digest,
        dest_layout_dir: &Path,
    ) -> Result<Sha256Digest, StoreError> {
        if self.is_read_denied(tier) {
            return Err(StoreError::Unauthorized("simulated 403".to_owned()));
        }
        let src_dir = self
            .state
            .lock()
            .expect("mutex")
            .image_layouts
            .get(&(tier, *digest))
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("image `{digest}` absent")))?;
        copy_dir_recursive_strict(&src_dir, dest_layout_dir)?;
        let verified = verify_oci_layout(dest_layout_dir, digest)?;
        Ok(verified.verified_config_digest)
    }

    fn fetch_blob_verified(
        &self,
        tier: StoreTier,
        digest: &Sha256Digest,
        dest: &Path,
        max_bytes: u64,
    ) -> Result<u64, StoreError> {
        if self.is_read_denied(tier) {
            return Err(StoreError::Unauthorized("simulated 403".to_owned()));
        }
        let bytes = self
            .state
            .lock()
            .expect("mutex")
            .blobs
            .get(&(tier, *digest))
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("blob `{digest}` absent")))?;
        let sz = bytes.len() as u64;
        if sz > max_bytes {
            return Err(StoreError::DigestMismatch(format!(
                "blob `{digest}` size {sz} > max_bytes {max_bytes}"
            )));
        }
        let actual = Sha256Digest::hash_bytes(&bytes);
        if &actual != digest {
            return Err(StoreError::DigestMismatch(format!(
                "corrupted stored blob `{actual}` != `{digest}`"
            )));
        }
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        }
        fs::write(dest, &bytes).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        Ok(sz)
    }

    fn push_untouched_oci_layout(
        &self,
        tier: StoreTier,
        layout_dir: &Path,
        expected_manifest: &Sha256Digest,
        anchor_tag: &LookupTag,
    ) -> Result<(), StoreError> {
        let verified = verify_oci_layout(layout_dir, expected_manifest)?;
        let snapshot = layout_dir.parent().unwrap_or(layout_dir).join(format!(
            ".inmem-oci-{}",
            verified.manifest_digest.prefix16()
        ));
        if snapshot.exists() {
            fs::remove_dir_all(&snapshot).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        }
        copy_dir_recursive_strict(layout_dir, &snapshot)?;
        let mut st = self.state.lock().expect("mutex");
        st.image_layouts
            .insert((tier, *expected_manifest), snapshot);
        st.committed_tags_order.push((tier, anchor_tag.clone()));
        Ok(())
    }

    fn upload_verified_blob(
        &self,
        tier: StoreTier,
        path: &Path,
        expected_digest: &Sha256Digest,
        expected_size: u64,
    ) -> Result<(), StoreError> {
        let (actual_digest, actual_size) = hash_local_file(path)?;
        if &actual_digest != expected_digest || actual_size != expected_size {
            return Err(StoreError::DigestMismatch(format!(
                "local blob mismatch: ({actual_digest}, {actual_size}) != ({expected_digest}, {expected_size})"
            )));
        }
        let bytes = fs::read(path).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        self.state
            .lock()
            .expect("mutex")
            .blobs
            .insert((tier, *expected_digest), bytes);
        Ok(())
    }

    fn put_claim_artifact(
        &self,
        tier: StoreTier,
        tag: &LookupTag,
        claim_bytes: &[u8],
        bundle_blob: &BlobRef,
        payload_blobs: &[BlobDescriptor],
    ) -> Result<(), StoreError> {
        if Sha256Digest::hash_bytes(&bundle_blob.bytes) != bundle_blob.digest {
            return Err(StoreError::DigestMismatch(
                "bundle digest mismatch".to_owned(),
            ));
        }
        let mut st = self.state.lock().expect("mutex");
        for pb in payload_blobs {
            if !st.blobs.contains_key(&(tier, pb.digest)) {
                return Err(StoreError::NotFound(format!(
                    "payload blob `{}` was not uploaded before put_claim_artifact",
                    pb.digest
                )));
            }
        }
        st.bundle_upload_count
            .entry((tier, bundle_blob.digest))
            .or_insert(1);
        st.blobs
            .insert((tier, bundle_blob.digest), bundle_blob.bytes.clone());
        st.claims.insert(
            (tier, tag.clone()),
            RawClaimArtifact {
                claim_bytes: claim_bytes.to_vec(),
                bundle_bytes: bundle_blob.bytes.clone(),
                payload_layers: payload_blobs.to_vec(),
            },
        );
        st.committed_tags_order.push((tier, tag.clone()));
        Ok(())
    }
}

fn copy_dir_recursive_strict(src: &Path, dst: &Path) -> Result<(), StoreError> {
    fs::create_dir_all(dst).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
    for ent_res in fs::read_dir(src).map_err(|e| StoreError::InvalidFormat(e.to_string()))? {
        let ent = ent_res.map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        let sp = ent.path();
        let dp = dst.join(ent.file_name());
        let meta =
            fs::symlink_metadata(&sp).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        if meta.file_type().is_symlink() {
            return Err(StoreError::DigestMismatch(
                "forbidden symlink in OCI layout copy".to_owned(),
            ));
        }
        if meta.file_type().is_dir() {
            copy_dir_recursive_strict(&sp, &dp)?;
        } else {
            fs::copy(&sp, &dp).map_err(|e| StoreError::InvalidFormat(e.to_string()))?;
        }
    }
    Ok(())
}
