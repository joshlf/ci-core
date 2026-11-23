//! Paginated read-only `GitHubApi` implementation (`ci.yml`) and isolated
//! `GitHubRerunClient` (`review-rerun.yml` ONLY, `per_page=100`, `0` cancel
//! calls).

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use backon::{BlockingRetryable, ExponentialBuilder};
use ci_core_model::store::{
    GhApiError, GitHubApi, MergeMethod, MergeQueueEntry, MergeQueueEntryState, MergeQueueSnapshot,
    PrReview, PrReviewState, RunArtifactMeta,
};
use ci_core_model::types::{GitOid, ReferencedWorkflow, RepoSlug, UnixSecs, WorkflowRunMeta};
use jiff::Timestamp;
use reqwest::StatusCode;
use reqwest::blocking::Client;
use reqwest::redirect::Policy as RedirectPolicy;
use serde::Deserialize;
use url::Url;

const DEFAULT_GITHUB_API_BASE: &str = "https://api.github.com";

fn gh_retry_policy() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(250))
        .with_max_delay(Duration::from_secs(4))
        .with_max_times(3)
        .with_jitter()
}

fn is_retryable_status(st: StatusCode) -> bool {
    st.is_server_error() || st == StatusCode::TOO_MANY_REQUESTS
}

/// Parses RFC 8288 `Link` response headers (`<...>; param; ...`, respecting
/// commas inside `<...>`) and extracts `rel="next"` if present.
pub fn parse_link_next_url(link_header: &str) -> Option<String> {
    let mut rest = link_header.trim();
    while !rest.is_empty() {
        let rest_after_lt = rest.strip_prefix('<')?;
        let (target, after_gt) = rest_after_lt.split_once('>')?;
        let (params_str, next_entry) = find_next_link_entry(after_gt);
        let has_next_rel = params_str.split(';').map(str::trim).any(|param| {
            if let Some((k, v)) = param.split_once('=')
                && k.trim().eq_ignore_ascii_case("rel")
            {
                let unquoted = v.trim().trim_matches('"');
                unquoted
                    .split_ascii_whitespace()
                    .any(|tok| tok.eq_ignore_ascii_case("next"))
            } else {
                false
            }
        });
        if has_next_rel {
            return Some(target.trim().to_owned());
        }
        rest = next_entry.trim();
    }
    None
}

fn find_next_link_entry(s: &str) -> (&str, &str) {
    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_quotes {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
        } else if ch == ',' && !in_quotes {
            return (&s[..idx], &s[idx + 1..]);
        }
    }
    (s, "")
}

/// Strictly read-only HTTP GitHub API client used inside `ci.yml` (`plan`,
/// `publish`, `gate`).
pub struct HttpGitHubApi {
    api_client: Client,
    redirect_no_auth_client: Client,
    api_base: String,
    api_base_url: Url,
    slug: RepoSlug,
    token: Option<String>,
}

#[derive(Debug)]
enum AttemptErr {
    Transient(String),
    Fatal(GhApiError),
}

impl HttpGitHubApi {
    /// Creates a new read-only `HttpGitHubApi` client.
    pub fn new(
        slug: RepoSlug,
        token: Option<String>,
        api_base: Option<String>,
    ) -> Result<Self, GhApiError> {
        let api_client = Client::builder()
            .redirect(RedirectPolicy::none())
            .timeout(Duration::from_secs(60))
            .user_agent("ci-core/0.1.0")
            .build()
            .map_err(|e| GhApiError::Request(e.to_string()))?;
        let redirect_no_auth_client = Client::builder()
            .redirect(RedirectPolicy::limited(5))
            .timeout(Duration::from_secs(120))
            .user_agent("ci-core/0.1.0")
            .build()
            .map_err(|e| GhApiError::Request(e.to_string()))?;
        let cleaned_base = api_base
            .unwrap_or_else(|| DEFAULT_GITHUB_API_BASE.to_owned())
            .trim_end_matches('/')
            .to_owned();
        let api_base_url = Url::parse(&cleaned_base)
            .map_err(|e| GhApiError::Request(format!("invalid api_base {cleaned_base:?}: {e}")))?;
        Ok(Self {
            api_client,
            redirect_no_auth_client,
            api_base: cleaned_base,
            api_base_url,
            slug,
            token: token.filter(|t| !t.trim().is_empty()),
        })
    }

    fn verify_same_origin_next_url(&self, raw_next: String) -> Result<String, GhApiError> {
        let parsed = self
            .api_base_url
            .join(&raw_next)
            .map_err(|e| GhApiError::Request(format!("invalid Link next URL {raw_next:?}: {e}")))?;
        if parsed.origin() != self.api_base_url.origin() {
            return Err(GhApiError::Request(format!(
                "refusing cross-origin Link pagination URL `{parsed}` (expected origin `{:?}`)",
                self.api_base_url.origin()
            )));
        }
        Ok(parsed.into())
    }

    fn get_json_with_next(
        &self,
        url: &str,
    ) -> Result<(serde_json::Value, Option<String>), GhApiError> {
        (|| {
            let mut req = self
                .api_client
                .get(url)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28");
            if let Some(ref tok) = self.token {
                req = req.header("Authorization", format!("Bearer {tok}"));
            }
            let resp = req
                .send()
                .map_err(|e| AttemptErr::Transient(e.to_string()))?;
            let st = resp.status();
            if st == StatusCode::NOT_FOUND {
                return Err(AttemptErr::Fatal(GhApiError::NotFound(url.to_owned())));
            }
            if is_retryable_status(st) {
                let body = resp.text().unwrap_or_default();
                return Err(AttemptErr::Transient(format!(
                    "GET {url} returned HTTP {st}: {body}"
                )));
            }
            if !st.is_success() {
                let body = resp.text().unwrap_or_default();
                return Err(AttemptErr::Fatal(GhApiError::Request(format!(
                    "GET {url} returned HTTP {st}: {body}"
                ))));
            }
            let next = match resp
                .headers()
                .get("link")
                .and_then(|h| h.to_str().ok())
                .and_then(parse_link_next_url)
            {
                Some(raw_u) => Some(
                    self.verify_same_origin_next_url(raw_u)
                        .map_err(AttemptErr::Fatal)?,
                ),
                None => None,
            };
            let val: serde_json::Value = resp
                .json()
                .map_err(|e| AttemptErr::Transient(format!("JSON decode {url}: {e}")))?;
            Ok((val, next))
        })
        .retry(gh_retry_policy())
        .when(|e| matches!(e, AttemptErr::Transient(_)))
        .call()
        .map_err(|e| match e {
            AttemptErr::Transient(msg) => GhApiError::Request(msg),
            AttemptErr::Fatal(err) => err,
        })
    }

    fn paginate_array(&self, first_url: &str) -> Result<Vec<serde_json::Value>, GhApiError> {
        let mut out = Vec::new();
        let mut next_url = Some(first_url.to_owned());
        while let Some(url) = next_url {
            let (val, nxt) = self.get_json_with_next(&url)?;
            let arr = val
                .as_array()
                .ok_or_else(|| GhApiError::Request(format!("expected JSON array from {url}")))?;
            out.extend(arr.iter().cloned());
            next_url = nxt;
        }
        Ok(out)
    }

    fn post_graphql(
        &self,
        query: &str,
        variables: serde_json::Value,
    ) -> Result<serde_json::Value, GhApiError> {
        let url = format!("{}/graphql", self.api_base);
        let tok = self.token.as_deref().ok_or_else(|| {
            GhApiError::Request("GraphQL mergeQueue query requires GITHUB_TOKEN".to_owned())
        })?;
        (|| {
            let resp = self
                .api_client
                .post(&url)
                .header("Authorization", format!("Bearer {tok}"))
                .header("Accept", "application/vnd.github+json")
                .json(&serde_json::json!({
                    "query": query,
                    "variables": variables,
                }))
                .send()
                .map_err(|e| AttemptErr::Transient(e.to_string()))?;
            let st = resp.status();
            if is_retryable_status(st) {
                return Err(AttemptErr::Transient(format!(
                    "POST /graphql returned HTTP {st}"
                )));
            }
            if !st.is_success() {
                return Err(AttemptErr::Fatal(GhApiError::Request(format!(
                    "POST /graphql returned HTTP {st}"
                ))));
            }
            let val: serde_json::Value = resp
                .json()
                .map_err(|e| AttemptErr::Transient(e.to_string()))?;
            if let Some(errs) = val.get("errors").and_then(serde_json::Value::as_array)
                && !errs.is_empty()
            {
                return Err(AttemptErr::Fatal(GhApiError::Request(format!(
                    "GraphQL errors: {errs:?}"
                ))));
            }
            Ok(val)
        })
        .retry(gh_retry_policy())
        .when(|e| matches!(e, AttemptErr::Transient(_)))
        .call()
        .map_err(|e| match e {
            AttemptErr::Transient(msg) => GhApiError::Request(msg),
            AttemptErr::Fatal(err) => err,
        })
    }
}

fn parse_iso8601_to_unix_secs(s: &str) -> Result<UnixSecs, GhApiError> {
    let ts: Timestamp = s
        .trim()
        .parse()
        .map_err(|e| GhApiError::Request(format!("invalid RFC 3339 timestamp {s:?}: {e}")))?;
    let secs = u64::try_from(ts.as_second())
        .map_err(|_| GhApiError::Request(format!("pre-1970 timestamp {s:?}")))?;
    Ok(UnixSecs(secs))
}

#[derive(Deserialize)]
struct RawApiReview {
    id: u64,
    user: Option<RawApiUser>,
    state: String,
    commit_id: Option<String>,
    body: Option<String>,
    submitted_at: Option<String>,
}

#[derive(Deserialize)]
struct RawApiUser {
    id: u64,
}

#[derive(Deserialize)]
struct RawApiRun {
    path: String,
    workflow_id: u64,
    workflow_url: String,
    #[serde(default)]
    referenced_workflows: Vec<RawApiRefWf>,
}

#[derive(Deserialize)]
struct RawApiRefWf {
    path: String,
    sha: String,
    #[serde(rename = "ref")]
    ref_str: Option<String>,
}

impl RawApiRun {
    fn into_meta(self) -> Result<WorkflowRunMeta, GhApiError> {
        let is_org_required_workflow =
            WorkflowRunMeta::parse_is_org_required_workflow(&self.workflow_url, self.workflow_id)
                .map_err(GhApiError::Request)?;
        let mut referenced_workflows = Vec::with_capacity(self.referenced_workflows.len());
        for rw in self.referenced_workflows {
            let sha = GitOid::from_hex(&rw.sha)
                .map_err(|e| GhApiError::Request(format!("referenced_workflows sha: {e}")))?;
            referenced_workflows.push(ReferencedWorkflow {
                path: rw.path,
                sha,
                ref_str: rw.ref_str,
            });
        }
        Ok(WorkflowRunMeta {
            path: self.path,
            workflow_id: self.workflow_id,
            is_org_required_workflow,
            referenced_workflows,
        })
    }
}

impl GitHubApi for HttpGitHubApi {
    fn list_pr_reviews_all(&self, pr_number: u64) -> Result<Vec<PrReview>, GhApiError> {
        let url = format!(
            "{}/repos/{}/pulls/{pr_number}/reviews?per_page=100",
            self.api_base,
            self.slug.canonical()
        );
        let raw_items = self.paginate_array(&url)?;
        let mut reviews = Vec::with_capacity(raw_items.len());
        for item in raw_items {
            let rr: RawApiReview = serde_json::from_value(item)
                .map_err(|e| GhApiError::Request(format!("PR review decode: {e}")))?;
            let Some(user) = rr.user else { continue };
            let state = match rr.state.as_str() {
                "APPROVED" => PrReviewState::Approved,
                "CHANGES_REQUESTED" => PrReviewState::ChangesRequested,
                "DISMISSED" => PrReviewState::Dismissed,
                "COMMENTED" => PrReviewState::Commented,
                "PENDING" => PrReviewState::Pending,
                _ => continue,
            };
            let submitted_at = match rr.submitted_at {
                Some(ref ts) => parse_iso8601_to_unix_secs(ts)?,
                None => UnixSecs(0),
            };
            let commit_id = rr
                .commit_id
                .as_deref()
                .and_then(|s| GitOid::from_hex(s).ok());
            reviews.push(PrReview {
                review_id: rr.id,
                user_id: user.id,
                state,
                commit_id,
                body: rr.body.unwrap_or_default(),
                submitted_at,
            });
        }
        Ok(reviews)
    }

    fn get_merge_queue(&self, branch: &str) -> Result<MergeQueueSnapshot, GhApiError> {
        const QUERY: &str = r#"
            query($owner: String!, $name: String!, $branch: String!, $cursor: String) {
              repository(owner: $owner, name: $name) {
                mergeQueue(branch: $branch) {
                  configuration { mergeMethod }
                  entries(first: 100, after: $cursor) {
                    pageInfo { hasNextPage endCursor }
                    nodes {
                      state
                      headCommit { oid }
                      baseCommit { oid }
                      pullRequest { number }
                    }
                  }
                }
              }
            }
        "#;
        let mut cursor: Option<String> = None;
        let mut merge_method_opt: Option<MergeMethod> = None;
        let mut entries = Vec::new();

        loop {
            let val = self.post_graphql(
                QUERY,
                serde_json::json!({
                    "owner": self.slug.owner(),
                    "name": self.slug.repo(),
                    "branch": branch,
                    "cursor": cursor,
                }),
            )?;
            let mq = val
                .pointer("/data/repository/mergeQueue")
                .filter(|v| !v.is_null())
                .ok_or_else(|| {
                    GhApiError::NotFound(format!("mergeQueue not enabled on branch `{branch}`"))
                })?;

            if merge_method_opt.is_none() {
                let mm_str = mq
                    .pointer("/configuration/mergeMethod")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("MERGE");
                let mm = match mm_str {
                    "MERGE" => MergeMethod::Merge,
                    "SQUASH" => MergeMethod::Squash,
                    "REBASE" => MergeMethod::Rebase,
                    other => {
                        return Err(GhApiError::Request(format!(
                            "unsupported mergeQueue mergeMethod {other:?}"
                        )));
                    }
                };
                merge_method_opt = Some(mm);
            }

            if let Some(nodes) = mq
                .pointer("/entries/nodes")
                .and_then(serde_json::Value::as_array)
            {
                for node in nodes {
                    if node.is_null() {
                        continue;
                    }
                    let pr_number = node
                        .pointer("/pullRequest/number")
                        .and_then(serde_json::Value::as_u64)
                        .ok_or_else(|| {
                            GhApiError::Request("mergeQueue entry missing PR number".to_owned())
                        })?;
                    let head_s = node
                        .pointer("/headCommit/oid")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            GhApiError::Request(
                                "mergeQueue entry missing headCommit.oid".to_owned(),
                            )
                        })?;
                    let head_oid =
                        GitOid::from_hex(head_s).map_err(|e| GhApiError::Request(e.to_string()))?;
                    let base_oid = node
                        .pointer("/baseCommit/oid")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|s| GitOid::from_hex(s).ok());
                    let state_s = node
                        .get("state")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("QUEUED");
                    let state = match state_s {
                        "LOCKED" => MergeQueueEntryState::Locked,
                        "AWAITING_CHECKS" => MergeQueueEntryState::AwaitingChecks,
                        "MERGEABLE" => MergeQueueEntryState::Mergeable,
                        "UNMERGEABLE" => MergeQueueEntryState::Unmergeable,
                        _ => MergeQueueEntryState::Queued,
                    };
                    entries.push(MergeQueueEntry {
                        pr_number,
                        head_oid,
                        base_oid,
                        state,
                    });
                }
            }

            let has_next = mq
                .pointer("/entries/pageInfo/hasNextPage")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if !has_next {
                break;
            }
            cursor = mq
                .pointer("/entries/pageInfo/endCursor")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            if cursor.is_none() {
                break;
            }
        }

        Ok(MergeQueueSnapshot {
            merge_method: merge_method_opt.unwrap_or(MergeMethod::Merge),
            entries,
        })
    }

    fn get_run_metadata(&self, run_id: u64) -> Result<WorkflowRunMeta, GhApiError> {
        let url = format!(
            "{}/repos/{}/actions/runs/{run_id}",
            self.api_base,
            self.slug.canonical()
        );
        let (val, _) = self.get_json_with_next(&url)?;
        let raw: RawApiRun = serde_json::from_value(val)
            .map_err(|e| GhApiError::Request(format!("actions/runs/{run_id}: {e}")))?;
        raw.into_meta()
    }

    fn get_codeowners_errors(&self, git_sha: &GitOid) -> Result<Vec<String>, GhApiError> {
        let url = format!(
            "{}/repos/{}/codeowners/errors?ref={git_sha}",
            self.api_base,
            self.slug.canonical()
        );
        let (val, _) = self.get_json_with_next(&url)?;
        let mut out = Vec::new();
        if let Some(errs) = val.get("errors").and_then(serde_json::Value::as_array) {
            for e in errs {
                let msg = e
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| e.to_string());
                out.push(msg);
            }
        }
        Ok(out)
    }

    fn list_run_artifacts(
        &self,
        run_id: u64,
        name_filter: Option<&str>,
    ) -> Result<Vec<RunArtifactMeta>, GhApiError> {
        let mut out = Vec::new();
        let mut initial = Url::parse(&format!(
            "{}/repos/{}/actions/runs/{run_id}/artifacts",
            self.api_base,
            self.slug.canonical()
        ))
        .map_err(|e| GhApiError::Request(e.to_string()))?;
        {
            let mut qp = initial.query_pairs_mut();
            qp.append_pair("per_page", "100");
            if let Some(nf) = name_filter {
                qp.append_pair("name", nf);
            }
        }
        let mut next_url: Option<String> = Some(initial.into());

        while let Some(url) = next_url {
            let (val, nxt) = self.get_json_with_next(&url)?;
            if let Some(arr) = val.get("artifacts").and_then(serde_json::Value::as_array) {
                for a in arr {
                    let expired = a
                        .get("expired")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    if expired {
                        continue;
                    }
                    let id = a
                        .get("id")
                        .and_then(serde_json::Value::as_u64)
                        .ok_or_else(|| GhApiError::Request("artifact missing id".to_owned()))?;
                    let name = a
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let size_in_bytes = a
                        .get("size_in_bytes")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);
                    out.push(RunArtifactMeta {
                        id,
                        name,
                        size_in_bytes,
                        expired,
                    });
                }
            }
            next_url = nxt;
        }
        Ok(out)
    }

    fn download_artifact_zip(&self, artifact_id: u64, dest: &Path) -> Result<(), GhApiError> {
        let url = format!(
            "{}/repos/{}/actions/artifacts/{artifact_id}/zip",
            self.api_base,
            self.slug.canonical()
        );
        (|| {
            let mut req = self
                .api_client
                .get(&url)
                .header("Accept", "application/vnd.github+json");
            if let Some(ref tok) = self.token {
                req = req.header("Authorization", format!("Bearer {tok}"));
            }
            let mut resp = req
                .send()
                .map_err(|e| AttemptErr::Transient(e.to_string()))?;
            if resp.status().is_redirection() {
                // Strip `Authorization` across `302` blob-storage redirect.
                let loc = resp
                    .headers()
                    .get("location")
                    .and_then(|h| h.to_str().ok())
                    .ok_or_else(|| {
                        AttemptErr::Fatal(GhApiError::Request("302 without Location".to_owned()))
                    })?
                    .to_owned();
                let resolved = self
                    .api_base_url
                    .join(&loc)
                    .map_err(|e| AttemptErr::Fatal(GhApiError::Request(e.to_string())))?;
                resp = self
                    .redirect_no_auth_client
                    .get(resolved)
                    .send()
                    .map_err(|e| AttemptErr::Transient(e.to_string()))?;
            }
            let st = resp.status();
            if st == StatusCode::NOT_FOUND {
                return Err(AttemptErr::Fatal(GhApiError::NotFound(url.clone())));
            }
            if is_retryable_status(st) {
                return Err(AttemptErr::Transient(format!(
                    "download artifact {artifact_id} returned HTTP {st}"
                )));
            }
            if !st.is_success() {
                return Err(AttemptErr::Fatal(GhApiError::Request(format!(
                    "download artifact {artifact_id} returned HTTP {st}"
                ))));
            }
            if let Some(p) = dest.parent() {
                fs::create_dir_all(p)
                    .map_err(|e| AttemptErr::Fatal(GhApiError::Request(e.to_string())))?;
            }
            let tmp_dest = dest.with_extension("zip.part");
            let mut f = File::create(&tmp_dest)
                .map_err(|e| AttemptErr::Fatal(GhApiError::Request(e.to_string())))?;
            let mut buf = [0u8; 65_536];
            loop {
                let n = resp.read(&mut buf).map_err(|e| {
                    let _ = fs::remove_file(&tmp_dest);
                    AttemptErr::Transient(e.to_string())
                })?;
                if n == 0 {
                    break;
                }
                f.write_all(&buf[..n]).map_err(|e| {
                    let _ = fs::remove_file(&tmp_dest);
                    AttemptErr::Fatal(GhApiError::Request(e.to_string()))
                })?;
            }
            f.sync_all()
                .map_err(|e| AttemptErr::Fatal(GhApiError::Request(e.to_string())))?;
            drop(f);
            fs::rename(&tmp_dest, dest)
                .map_err(|e| AttemptErr::Fatal(GhApiError::Request(e.to_string())))
        })
        .retry(gh_retry_policy())
        .when(|e| matches!(e, AttemptErr::Transient(_)))
        .call()
        .map_err(|e| match e {
            AttemptErr::Transient(msg) => GhApiError::Request(msg),
            AttemptErr::Fatal(err) => err,
        })
    }
}

/// Open PR summary returned by fork-safe `list_open_prs_matching_head`.
#[derive(Debug, Clone)]
pub struct OpenPrSummary {
    /// PR number.
    pub number: u64,
    /// `pr.head.sha`.
    pub head_sha: GitOid,
}

/// Observed run entry returned by `list_pr_workflow_runs`.
#[derive(Debug, Clone)]
pub struct ObservedPrWorkflowRun {
    /// Numeric `run_id`.
    pub run_id: u64,
    /// Latest `run_attempt`.
    pub run_attempt: u32,
    /// Run status (`"queued"`, `"in_progress"`, `"completed"`).
    pub status: String,
    /// Run metadata (`path`, `workflow_id`, `is_org_required_workflow`, `referenced_workflows`).
    pub meta: WorkflowRunMeta,
}

/// Observed job inside a workflow run attempt.
#[derive(Debug, Clone)]
pub struct ObservedRunJob {
    /// Job display name (e.g. `"ci / plan"`, `"plan"`, `"ci / gate"`).
    pub name: String,
    /// Job status (`"queued"`, `"in_progress"`, `"completed"`).
    pub status: String,
    /// Job conclusion (`Some("success")`, `Some("failure")`, `Some("skipped")`, etc.).
    pub conclusion: Option<String>,
}

/// Isolated GitHub REST client used ONLY by `ci-core review-rerun` (`actions: write`
/// strictly scoped to `/rerun` and `/rerun-failed-jobs`, with zero `/cancel`
/// method).
pub struct GitHubRerunClient {
    ro: HttpGitHubApi,
}

impl GitHubRerunClient {
    /// Creates an isolated `GitHubRerunClient`.
    pub fn new(
        slug: RepoSlug,
        token: String,
        api_base: Option<String>,
    ) -> Result<Self, GhApiError> {
        Ok(Self {
            ro: HttpGitHubApi::new(slug, Some(token), api_base)?,
        })
    }

    /// Borrows the underlying read-only `GitHubApi`.
    pub fn read_only(&self) -> &HttpGitHubApi {
        &self.ro
    }

    /// Fork- and stack-safe open PR lookup (`GET /repos/{o}/{r}/pulls?state=open&per_page=100`
    /// filtered by `pr.head.sha == target_head_sha`, avoiding `/commits/{sha}/pulls`
    /// which returns `[]` on cross-repo fork PRs and covering stacked PRs whose
    /// `base.ref != default_branch`).
    pub fn list_open_prs_matching_head(
        &self,
        _default_branch: &str,
        target_head_sha: &GitOid,
    ) -> Result<Vec<OpenPrSummary>, GhApiError> {
        let url = format!(
            "{}/repos/{}/pulls?state=open&per_page=100",
            self.ro.api_base,
            self.ro.slug.canonical()
        );
        let items = self.ro.paginate_array(&url)?;
        let mut matches = Vec::new();
        for item in items {
            let Some(num) = item.get("number").and_then(serde_json::Value::as_u64) else {
                continue;
            };
            let Some(hstr) = item
                .pointer("/head/sha")
                .and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            if let Ok(oid) = GitOid::from_hex(hstr)
                && &oid == target_head_sha
            {
                matches.push(OpenPrSummary {
                    number: num,
                    head_sha: oid,
                });
            }
        }
        Ok(matches)
    }

    /// Paginates `GET /repos/{o}/{r}/actions/runs?head_sha={sha}&event=pull_request&per_page=100`.
    pub fn list_pr_workflow_runs(
        &self,
        head_sha: &GitOid,
    ) -> Result<Vec<ObservedPrWorkflowRun>, GhApiError> {
        let mut out = Vec::new();
        let mut next_url = Some(format!(
            "{}/repos/{}/actions/runs?head_sha={head_sha}&event=pull_request&per_page=100",
            self.ro.api_base,
            self.ro.slug.canonical()
        ));
        while let Some(url) = next_url {
            let (val, nxt) = self.ro.get_json_with_next(&url)?;
            if let Some(arr) = val
                .get("workflow_runs")
                .and_then(serde_json::Value::as_array)
            {
                for r in arr {
                    let Some(run_id) = r.get("id").and_then(serde_json::Value::as_u64) else {
                        continue;
                    };
                    let run_attempt = r
                        .get("run_attempt")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(1) as u32;
                    let status = r
                        .get("status")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("completed")
                        .to_owned();
                    let raw: RawApiRun = serde_json::from_value(r.clone())
                        .map_err(|e| GhApiError::Request(format!("workflow_run decode: {e}")))?;
                    out.push(ObservedPrWorkflowRun {
                        run_id,
                        run_attempt,
                        status,
                        meta: raw.into_meta()?,
                    });
                }
            }
            next_url = nxt;
        }
        Ok(out)
    }

    /// Paginates `GET /repos/{o}/{r}/actions/runs/{id}/attempts/{A}/jobs?per_page=100`
    /// across `<= 256` shards.
    pub fn list_attempt_jobs_all(
        &self,
        run_id: u64,
        attempt: u32,
    ) -> Result<Vec<ObservedRunJob>, GhApiError> {
        let mut out = Vec::new();
        let mut next_url = Some(format!(
            "{}/repos/{}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100",
            self.ro.api_base,
            self.ro.slug.canonical()
        ));
        while let Some(url) = next_url {
            let (val, nxt) = self.ro.get_json_with_next(&url)?;
            if let Some(arr) = val.get("jobs").and_then(serde_json::Value::as_array) {
                for j in arr {
                    let name = j
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let status = j
                        .get("status")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let conclusion = j
                        .get("conclusion")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    out.push(ObservedRunJob {
                        name,
                        status,
                        conclusion,
                    });
                }
            }
            next_url = nxt;
        }
        Ok(out)
    }

    /// Triggers `POST /repos/{o}/{r}/actions/runs/{run_id}/rerun`.
    pub fn trigger_rerun_full(&self, run_id: u64) -> Result<(), GhApiError> {
        self.post_rerun_endpoint(run_id, "rerun")
    }

    /// Triggers `POST /repos/{o}/{r}/actions/runs/{run_id}/rerun-failed-jobs`.
    pub fn trigger_rerun_failed_jobs(&self, run_id: u64) -> Result<(), GhApiError> {
        self.post_rerun_endpoint(run_id, "rerun-failed-jobs")
    }

    fn post_rerun_endpoint(&self, run_id: u64, action: &str) -> Result<(), GhApiError> {
        let url = format!(
            "{}/repos/{}/actions/runs/{run_id}/{action}",
            self.ro.api_base,
            self.ro.slug.canonical()
        );
        let tok = self
            .ro
            .token
            .as_deref()
            .ok_or_else(|| GhApiError::Request("missing GITHUB_TOKEN".to_owned()))?;
        (|| {
            let resp = self
                .ro
                .api_client
                .post(&url)
                .header("Authorization", format!("Bearer {tok}"))
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .send()
                .map_err(|e| AttemptErr::Transient(e.to_string()))?;
            let st = resp.status();
            if is_retryable_status(st) {
                let b = resp.text().unwrap_or_default();
                return Err(AttemptErr::Transient(format!(
                    "POST {url} returned HTTP {st}: {b}"
                )));
            }
            if !st.is_success() {
                let b = resp.text().unwrap_or_default();
                return Err(AttemptErr::Fatal(GhApiError::Request(format!(
                    "POST {url} returned HTTP {st}: {b}"
                ))));
            }
            Ok(())
        })
        .retry(gh_retry_policy())
        .when(|e| matches!(e, AttemptErr::Transient(_)))
        .call()
        .map_err(|e| match e {
            AttemptErr::Transient(msg) => GhApiError::Request(msg),
            AttemptErr::Fatal(err) => err,
        })
    }
}
