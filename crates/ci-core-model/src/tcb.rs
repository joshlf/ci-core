//! Consumer-TCB classification (`EffectiveTcb`), `.github/CODEOWNERS` and
//! sibling-workflow anti-spoof validators, owner review projection, control-
//! plane transition resolution, and `pull_request` / `merge_group` attribution.

use std::collections::{BTreeMap, BTreeSet};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cargo_static::discover_cargo_configs_from_dir;
use crate::config::{ChecksConfig, InputSelector, expand_selectors_in_tree};
use crate::store::{MergeQueueEntry, MergeQueueEntryState, PrReview, PrReviewState};
use crate::tree::{
    EntryKind, SourceTree, TreeEntry, TreeError, compile_selector_globset, resolve_in_tree,
};
use crate::types::{
    CallerMode, CodeOwnerPrincipal, ControlPlanePolicy, ControlPlaneTransition, GitOid,
    NonEmptyVec, ReferencedWorkflow, RepoRelPath, SignerPolicy, TriggerEvent, WorkflowRunMeta,
};

const MAX_CODEOWNERS_BYTES: usize = 3_000_000;

/// Trust lattice for repository paths (`Untrusted < DataPin < ExecutableTcb`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathTrustClass {
    /// Ordinary source, fixture, or validated `non_tcb_workflows` / `non_tcb_subtrees`.
    Untrusted,
    /// Validated flat TOML data pin (`[pins.*].path`), gated on owner review at `gate`.
    DataPin,
    /// Consumer TCB path requiring owner review before `plan` schedules compute.
    ExecutableTcb,
}

impl PathTrustClass {
    /// Lattice join (`max`).
    pub fn join(self, other: Self) -> Self {
        self.max(other)
    }
}

/// Consumer-TCB authorization outcome recorded in `plan.json` and re-verified
/// in `publish` and `gate`.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TcbPlan {
    /// Only `Untrusted` paths changed (`0` owner review required).
    NotRequired,
    /// Unapproved `ExecutableTcb` paths changed on `pull_request` (`0` shards).
    Blocked {
        /// Sorted offending `ExecutableTcb` paths.
        paths: NonEmptyVec<RepoRelPath>,
    },
    /// `DataPin` or owner-approved `ExecutableTcb` paths changed.
    RequiresOwnerApproval {
        /// `(pr_number, pr_head_sha)` pairs that must hold live owner approval.
        required_prs: NonEmptyVec<(u64, GitOid)>,
        /// `Some` iff `control_plane()` changed between base and candidate.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        control_plane_transition: Option<ControlPlaneTransition>,
    },
}

/// Validation or policy error in `tcb.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TcbError {
    /// Tree inspection error.
    #[error(transparent)]
    Tree(#[from] TreeError),
    /// Symlink encountered at a zero-symlink core TCB path or directory prefix.
    #[error("forbidden symlink in core TCB path or ancestor `{0}`")]
    SymlinkViolation(RepoRelPath),
    /// `.cargo/config(.toml)` `include` cycle, escape, or missing target.
    #[error("cargo config TCB resolution failed: {0}")]
    CargoConfig(String),
    /// Caller or sibling workflow validation failure (`validate_workflows`).
    #[error("workflow validation error in `{workflow}`: {reason}")]
    WorkflowValidation {
        /// Workflow path.
        workflow: String,
        /// Rejection reason.
        reason: String,
    },
    /// `.github/CODEOWNERS` static validation failure (`validate_codeowners`).
    #[error("CODEOWNERS validation error: {0}")]
    CodeownersValidation(String),
    /// `referenced_workflows` runtime pinning failure (`verify_engine_workflows`).
    #[error("engine workflow pinning violation: {0}")]
    EngineWorkflowPin(String),
    /// `ControlPlaneTransition` base/candidate diverged from live `H_default`,
    /// or `TcbPlan::Blocked` reached control-plane resolution.
    #[error("control-plane resolution rejected: {0}")]
    ControlPlaneRejected(String),
    /// `merge_group` queue prefix replay or TCB authorization failure.
    #[error("merge_group TCB verification failed: {0}")]
    MergeGroupRejected(String),
}

impl From<crate::types::TypeError> for TcbError {
    fn from(err: crate::types::TypeError) -> Self {
        Self::Tree(TreeError::from(err))
    }
}

fn is_under_non_tcb_subtree(path: &RepoRelPath, non_tcb_subtrees: &[RepoRelPath]) -> bool {
    non_tcb_subtrees.iter().any(|sub| sub.is_prefix_of(path))
}

fn ensure_no_symlink_at_or_ancestors(
    tree: &dyn SourceTree,
    path: &RepoRelPath,
    check_self: bool,
) -> Result<(), TcbError> {
    for anc in path.proper_ancestors() {
        if tree.kind_of(&anc)? == Some(EntryKind::Symlink) {
            return Err(TcbError::SymlinkViolation(anc));
        }
    }
    if check_self && tree.kind_of(path)? == Some(EntryKind::Symlink) {
        return Err(TcbError::SymlinkViolation(path.clone()));
    }
    Ok(())
}

/// Compiles the anchored regex prefix `\A...` for a GitHub Actions job display
/// name (`job.name.unwrap_or(job_key)`), escaping regex metacharacters outside
/// `${{ ... }}` and replacing each `${{ ... }}` expression span with `.*`.
fn compile_job_display_pattern_prefix(raw_name: &str) -> (String, bool) {
    let mut pat = String::from(r"\A");
    let mut rest = raw_name;
    let mut had_expr = false;
    while let Some(open) = rest.find("${{") {
        pat.push_str(&regex::escape(&rest[..open]));
        had_expr = true;
        let after = &rest[open + 3..];
        if let Some(close) = after.find("}}") {
            pat.push_str(".*");
            rest = &after[close + 2..];
        } else {
            // Unclosed `${{` — treat remainder conservatively as wildcard `.*`.
            pat.push_str(".*");
            rest = "";
            break;
        }
    }
    pat.push_str(&regex::escape(rest));
    (pat, had_expr)
}

fn build_job_display_regexes(
    raw_name: &str,
    has_strategy_matrix: bool,
) -> Result<Vec<Regex>, String> {
    let (pat, had_expr) = compile_job_display_pattern_prefix(raw_name);
    let base_full = format!(r"{pat}\z");
    let mut out = vec![Regex::new(&base_full).map_err(|e| e.to_string())?];
    if has_strategy_matrix && !had_expr {
        let mat_full = format!(r"{pat} \(.*\)\z");
        out.push(Regex::new(&mat_full).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn build_job_prefix_slash_regexes(
    raw_name: &str,
    has_strategy_matrix: bool,
) -> Result<Vec<Regex>, String> {
    let (pat, had_expr) = compile_job_display_pattern_prefix(raw_name);
    let base_prefix = format!(r"{pat} / .*\z");
    let mut out = vec![Regex::new(&base_prefix).map_err(|e| e.to_string())?];
    if has_strategy_matrix && !had_expr {
        let mat_prefix = format!(r"{pat} \(.*\) / .*\z");
        out.push(Regex::new(&mat_prefix).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn yaml_map_get<'a>(
    map: &'a serde_yaml_ng::Mapping,
    key: &str,
) -> Option<&'a serde_yaml_ng::Value> {
    map.get(serde_yaml_ng::Value::String(key.to_owned()))
}

fn check_permissions_ceiling_for_sibling(
    perms: &serde_yaml_ng::Value,
    wf_path: &str,
    scope: &str,
) -> Result<(), TcbError> {
    match perms {
        serde_yaml_ng::Value::String(s) => {
            if s == "read-all" {
                Ok(())
            } else {
                Err(TcbError::WorkflowValidation {
                    workflow: wf_path.to_owned(),
                    reason: format!(
                        "{scope} `permissions: {s}` is forbidden (only `read-all` or an explicit map is allowed)"
                    ),
                })
            }
        }
        serde_yaml_ng::Value::Mapping(m) => {
            for (k_val, v_val) in m {
                let Some(k) = k_val.as_str() else {
                    return Err(TcbError::WorkflowValidation {
                        workflow: wf_path.to_owned(),
                        reason: format!("{scope} permissions key must be a string"),
                    });
                };
                let Some(v) = v_val.as_str() else {
                    return Err(TcbError::WorkflowValidation {
                        workflow: wf_path.to_owned(),
                        reason: format!("{scope} permissions `{k}` value must be a string"),
                    });
                };
                if !matches!(v, "read" | "write" | "none") {
                    return Err(TcbError::WorkflowValidation {
                        workflow: wf_path.to_owned(),
                        reason: format!("{scope} permissions `{k}: {v}` has invalid level"),
                    });
                }
                if matches!(k, "checks" | "statuses") && v == "write" {
                    return Err(TcbError::WorkflowValidation {
                        workflow: wf_path.to_owned(),
                        reason: format!(
                            "{scope} grants forbidden `{k}: write` (blocks check/status forgery)"
                        ),
                    });
                }
            }
            Ok(())
        }
        _ => Err(TcbError::WorkflowValidation {
            workflow: wf_path.to_owned(),
            reason: format!("{scope} `permissions` must be `read-all` or a mapping"),
        }),
    }
}

fn check_non_tcb_workflow_permissions(perms: &serde_yaml_ng::Value) -> bool {
    match perms {
        serde_yaml_ng::Value::String(s) => s == "read-all",
        serde_yaml_ng::Value::Mapping(m) => m.iter().all(|(kv, vv)| {
            let Some(k) = kv.as_str() else { return false };
            let Some(v) = vv.as_str() else { return false };
            matches!(
                (k, v),
                (_, "none")
                    | ("contents" | "actions", "read")
                    | ("security-events" | "id-token", "read" | "write")
            )
        }),
        _ => false,
    }
}

/// Checks sibling-job check-name anti-spoofing (incorporating Obligation `O2`:
/// unconditionally rejecting `"gate"` / `gate_check_name` matches across BOTH
/// step jobs and `job.uses` jobs, plus `caller_prefix` checks when `job.uses`
/// is present).
fn validate_sibling_jobs_anti_spoof(
    wf_path: &str,
    jobs_map: &serde_yaml_ng::Mapping,
    has_top_level_perms: bool,
    gate_check_name: &str,
    caller_prefix: Option<&str>,
) -> Result<(), TcbError> {
    if jobs_map.is_empty() {
        return Err(TcbError::WorkflowValidation {
            workflow: wf_path.to_owned(),
            reason: "workflow `jobs` must not be empty".to_owned(),
        });
    }
    for (jkey_val, jval) in jobs_map {
        let Some(job_key) = jkey_val.as_str() else {
            return Err(TcbError::WorkflowValidation {
                workflow: wf_path.to_owned(),
                reason: "job key must be a string".to_owned(),
            });
        };
        let Some(jmap) = jval.as_mapping() else {
            return Err(TcbError::WorkflowValidation {
                workflow: wf_path.to_owned(),
                reason: format!("job `{job_key}` must be a mapping"),
            });
        };

        if let Some(jperms) = yaml_map_get(jmap, "permissions") {
            check_permissions_ceiling_for_sibling(jperms, wf_path, &format!("job `{job_key}`"))?;
        } else if !has_top_level_perms {
            return Err(TcbError::WorkflowValidation {
                workflow: wf_path.to_owned(),
                reason: format!(
                    "job `{job_key}` lacks explicit `permissions:` and workflow has no top-level `permissions:`"
                ),
            });
        }

        let raw_display = match yaml_map_get(jmap, "name") {
            None => job_key,
            Some(serde_yaml_ng::Value::String(s)) => {
                if s.trim().is_empty() {
                    return Err(TcbError::WorkflowValidation {
                        workflow: wf_path.to_owned(),
                        reason: format!("job `{job_key}` has empty `name`"),
                    });
                }
                s.as_str()
            }
            Some(_) => {
                return Err(TcbError::WorkflowValidation {
                    workflow: wf_path.to_owned(),
                    reason: format!("job `{job_key}` `name` must be a string"),
                });
            }
        };

        let has_matrix = yaml_map_get(jmap, "strategy")
            .and_then(serde_yaml_ng::Value::as_mapping)
            .and_then(|s| yaml_map_get(s, "matrix"))
            .is_some();
        let has_uses = yaml_map_get(jmap, "uses").is_some();

        let exact_rxs = build_job_display_regexes(raw_display, has_matrix).map_err(|e| {
            TcbError::WorkflowValidation {
                workflow: wf_path.to_owned(),
                reason: e,
            }
        })?;

        // Obligation `O2`: unconditionally reject when `"gate"` or
        // `gate_check_name` matches `\A{E}\z` / `\A{E_mat}\z` across BOTH step
        // jobs and `job.uses` jobs (since a skipped `if: false` `job.uses`
        // caller emits a completed check run under `<caller_job_display_name>`).
        for rx in &exact_rxs {
            if rx.is_match("gate") || rx.is_match(gate_check_name) {
                return Err(TcbError::WorkflowValidation {
                    workflow: wf_path.to_owned(),
                    reason: format!(
                        "sibling job `{job_key}` (`{raw_display}`) can spoof required gate check `{gate_check_name}`"
                    ),
                });
            }
        }

        if has_uses && let Some(cp) = caller_prefix {
            for rx in &exact_rxs {
                if rx.is_match(cp) {
                    return Err(TcbError::WorkflowValidation {
                        workflow: wf_path.to_owned(),
                        reason: format!(
                            "reusable-workflow caller job `{job_key}` (`{raw_display}`) collides with caller prefix `{cp}`"
                        ),
                    });
                }
            }
            let prefix_rxs =
                build_job_prefix_slash_regexes(raw_display, has_matrix).map_err(|e| {
                    TcbError::WorkflowValidation {
                        workflow: wf_path.to_owned(),
                        reason: e,
                    }
                })?;
            for prx in &prefix_rxs {
                if prx.is_match(gate_check_name) {
                    return Err(TcbError::WorkflowValidation {
                        workflow: wf_path.to_owned(),
                        reason: format!(
                            "reusable-workflow caller job `{job_key}` (`{raw_display}`) prefix can spoof `{gate_check_name}`"
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}

fn read_regular_100644_yaml(
    tree: &dyn SourceTree,
    path: &RepoRelPath,
) -> Result<serde_yaml_ng::Mapping, TcbError> {
    ensure_no_symlink_at_or_ancestors(tree, path, true)?;
    let Some(TreeEntry::Regular { executable }) = tree.entry(path)? else {
        return Err(TcbError::WorkflowValidation {
            workflow: path.to_string(),
            reason: "workflow file does not exist as a regular file".to_owned(),
        });
    };
    if executable {
        return Err(TcbError::WorkflowValidation {
            workflow: path.to_string(),
            reason: "workflow file must be mode 100644 (non-executable)".to_owned(),
        });
    }
    let bytes = tree.read_blob(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|e| TcbError::WorkflowValidation {
        workflow: path.to_string(),
        reason: format!("invalid UTF-8: {e}"),
    })?;
    let val: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(text).map_err(|e| TcbError::WorkflowValidation {
            workflow: path.to_string(),
            reason: format!("YAML parse error: {e}"),
        })?;
    val.as_mapping()
        .cloned()
        .ok_or_else(|| TcbError::WorkflowValidation {
            workflow: path.to_string(),
            reason: "workflow root must be a YAML mapping".to_owned(),
        })
}

fn extract_on_trigger_names(
    wf_map: &serde_yaml_ng::Mapping,
    wf_path: &str,
) -> Result<(BTreeSet<String>, Option<serde_yaml_ng::Mapping>), TcbError> {
    let Some(on_val) = yaml_map_get(wf_map, "on") else {
        return Err(TcbError::WorkflowValidation {
            workflow: wf_path.to_owned(),
            reason: "missing `on:` trigger block".to_owned(),
        });
    };
    let mut names = BTreeSet::new();
    match on_val {
        serde_yaml_ng::Value::String(s) => {
            names.insert(s.clone());
            Ok((names, None))
        }
        serde_yaml_ng::Value::Sequence(seq) => {
            for item in seq {
                let s = item.as_str().ok_or_else(|| TcbError::WorkflowValidation {
                    workflow: wf_path.to_owned(),
                    reason: "`on:` sequence entry must be a string".to_owned(),
                })?;
                names.insert(s.to_owned());
            }
            Ok((names, None))
        }
        serde_yaml_ng::Value::Mapping(m) => {
            for k in m.keys() {
                let s = k.as_str().ok_or_else(|| TcbError::WorkflowValidation {
                    workflow: wf_path.to_owned(),
                    reason: "`on:` mapping key must be a string".to_owned(),
                })?;
                names.insert(s.to_owned());
            }
            Ok((names, Some(m.clone())))
        }
        _ => Err(TcbError::WorkflowValidation {
            workflow: wf_path.to_owned(),
            reason: "invalid `on:` trigger structure".to_owned(),
        }),
    }
}

fn validate_uses_pinned_to_trusted_sha(
    uses_str: &str,
    expected_uris: &[&str],
    trusted_shas: &[GitOid],
    wf_path: &str,
) -> Result<(), TcbError> {
    let Some((uri_part, sha_part)) = uses_str.split_once('@') else {
        return Err(TcbError::WorkflowValidation {
            workflow: wf_path.to_owned(),
            reason: format!("`uses: {uses_str}` missing `@<40-hex-sha>`"),
        });
    };
    if !expected_uris.contains(&uri_part) {
        return Err(TcbError::WorkflowValidation {
            workflow: wf_path.to_owned(),
            reason: format!("`uses` URI `{uri_part}` not in expected {expected_uris:?}"),
        });
    }
    let oid = GitOid::from_hex(sha_part).map_err(|_| TcbError::WorkflowValidation {
        workflow: wf_path.to_owned(),
        reason: format!("`uses` ref `{sha_part}` is not a 40-lower-hex commit SHA"),
    })?;
    if !trusted_shas.contains(&oid) {
        return Err(TcbError::WorkflowValidation {
            workflow: wf_path.to_owned(),
            reason: format!("`uses` SHA `{oid}` is not in repo.trusted_engine_shas"),
        });
    }
    Ok(())
}

fn validate_single_caller_job<'a>(
    wf_map: &'a serde_yaml_ng::Mapping,
    wf_path: &str,
    allowlisted_job_keys: &[&str],
) -> Result<(&'a str, &'a serde_yaml_ng::Mapping), TcbError> {
    let Some(jobs_map) = yaml_map_get(wf_map, "jobs").and_then(serde_yaml_ng::Value::as_mapping)
    else {
        return Err(TcbError::WorkflowValidation {
            workflow: wf_path.to_owned(),
            reason: "missing `jobs:` mapping".to_owned(),
        });
    };
    if jobs_map.len() != 1 {
        return Err(TcbError::WorkflowValidation {
            workflow: wf_path.to_owned(),
            reason: format!(
                "engine caller workflow must contain strictly 1 job, found {}",
                jobs_map.len()
            ),
        });
    }
    let (jkey_val, jval) = jobs_map.iter().next().expect("len == 1");
    let job_key = jkey_val
        .as_str()
        .ok_or_else(|| TcbError::WorkflowValidation {
            workflow: wf_path.to_owned(),
            reason: "job key must be a string".to_owned(),
        })?;
    let jmap = jval
        .as_mapping()
        .ok_or_else(|| TcbError::WorkflowValidation {
            workflow: wf_path.to_owned(),
            reason: "job value must be a mapping".to_owned(),
        })?;
    for kv in jmap.keys() {
        let k = kv.as_str().unwrap_or_default();
        if !allowlisted_job_keys.contains(&k) {
            return Err(TcbError::WorkflowValidation {
                workflow: wf_path.to_owned(),
                reason: format!(
                    "job `{job_key}` contains disallowed key `{k}` (allowed: {allowlisted_job_keys:?})"
                ),
            });
        }
    }
    Ok((job_key, jmap))
}

fn forbid_cancel_in_progress(
    wf_map: &serde_yaml_ng::Mapping,
    wf_path: &str,
) -> Result<(), TcbError> {
    if let Some(conc) =
        yaml_map_get(wf_map, "concurrency").and_then(serde_yaml_ng::Value::as_mapping)
        && yaml_map_get(conc, "cancel-in-progress") == Some(&serde_yaml_ng::Value::Bool(true))
    {
        return Err(TcbError::WorkflowValidation {
                workflow: wf_path.to_owned(),
                reason: "workflow-level `concurrency.cancel-in-progress: true` is forbidden on trusted callers".to_owned(),
            });
    }
    Ok(())
}

fn validate_engine_with_inputs(
    jmap: &serde_yaml_ng::Mapping,
    wf_path: &str,
    require_shadow_false: bool,
) -> Result<(), TcbError> {
    if let Some(with_val) = yaml_map_get(jmap, "with") {
        let Some(wmap) = with_val.as_mapping() else {
            return Err(TcbError::WorkflowValidation {
                workflow: wf_path.to_owned(),
                reason: "`with` must be a mapping".to_owned(),
            });
        };
        for (kv, vv) in wmap {
            let k = kv.as_str().unwrap_or_default();
            match k {
                "config_path" => {
                    if !vv.is_string() {
                        return Err(TcbError::WorkflowValidation {
                            workflow: wf_path.to_owned(),
                            reason: "`with.config_path` must be a string".to_owned(),
                        });
                    }
                }
                "shadow_mode" => {
                    let Some(b) = vv.as_bool() else {
                        return Err(TcbError::WorkflowValidation {
                            workflow: wf_path.to_owned(),
                            reason: "`with.shadow_mode` must be a literal boolean".to_owned(),
                        });
                    };
                    if require_shadow_false && b {
                        return Err(TcbError::WorkflowValidation {
                            workflow: wf_path.to_owned(),
                            reason: "`push_caller_workflow` must set `shadow_mode: false`"
                                .to_owned(),
                        });
                    }
                }
                "force_execute_all" => {
                    if !(vv.is_bool() || vv.is_string()) {
                        return Err(TcbError::WorkflowValidation {
                            workflow: wf_path.to_owned(),
                            reason: "`with.force_execute_all` must be a boolean or expression"
                                .to_owned(),
                        });
                    }
                }
                _ => {
                    return Err(TcbError::WorkflowValidation {
                        workflow: wf_path.to_owned(),
                        reason: format!("unknown `with` input `{k}` on engine caller"),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Validates caller workflows, hoisted review-companion workflows, and all
/// sibling `.github/workflows/*.{yml,yaml}` files in `tree` (`§4.2` + `O2`).
pub fn validate_workflows(tree: &dyn SourceTree, cfg: &ChecksConfig) -> Result<(), TcbError> {
    let github_dir = RepoRelPath::new(".github").expect("static");
    let wf_dir = RepoRelPath::new(".github/workflows").expect("static");
    if tree.kind_of(&github_dir)? == Some(EntryKind::Symlink) {
        return Err(TcbError::SymlinkViolation(github_dir));
    }
    if tree.kind_of(&wf_dir)? == Some(EntryKind::Symlink) {
        return Err(TcbError::SymlinkViolation(wf_dir));
    }

    let signer = cfg
        .repo
        .signer_policy()
        .map_err(|e| TcbError::WorkflowValidation {
            workflow: ".github/workflows".to_owned(),
            reason: e.to_string(),
        })?;
    let gate_check_name = cfg.tcb.caller.gate_check_name();
    let caller_prefix = cfg.tcb.caller.caller_prefix();

    let mut active_callers: BTreeSet<RepoRelPath> = BTreeSet::new();

    // 1. Validate caller workflow(s) per `CallerMode`.
    match &cfg.tcb.caller {
        CallerMode::RepoRuleset {
            caller_workflows, ..
        } => {
            let expected_prefix = caller_prefix.expect("RepoRuleset has caller_prefix");
            let mut covered_triggers: BTreeSet<String> = BTreeSet::new();
            for cw in caller_workflows {
                active_callers.insert(cw.clone());
                let wf_map = read_regular_100644_yaml(tree, cw)?;
                let cw_str = cw.as_str();
                let (triggers, on_map_opt) = extract_on_trigger_names(&wf_map, cw_str)?;
                if triggers.is_empty() {
                    return Err(TcbError::WorkflowValidation {
                        workflow: cw_str.to_owned(),
                        reason: "caller workflow `on:` must be non-empty".to_owned(),
                    });
                }
                for trig in &triggers {
                    if !matches!(trig.as_str(), "pull_request" | "merge_group" | "push") {
                        return Err(TcbError::WorkflowValidation {
                            workflow: cw_str.to_owned(),
                            reason: format!(
                                "caller workflow declares unsupported trigger `{trig}` (allowed subset: pull_request, merge_group, push)"
                            ),
                        });
                    }
                    if !covered_triggers.insert(trig.clone()) {
                        return Err(TcbError::WorkflowValidation {
                            workflow: cw_str.to_owned(),
                            reason: format!("duplicate trigger `{trig}` across caller_workflows"),
                        });
                    }
                }
                if triggers.contains("merge_group") || triggers.contains("push") {
                    forbid_cancel_in_progress(&wf_map, cw_str)?;
                }
                if let Some(ref on_map) = on_map_opt {
                    for trig in &triggers {
                        if let Some(tmap) =
                            yaml_map_get(on_map, trig).and_then(serde_yaml_ng::Value::as_mapping)
                        {
                            if yaml_map_get(tmap, "paths").is_some()
                                || yaml_map_get(tmap, "paths-ignore").is_some()
                            {
                                return Err(TcbError::WorkflowValidation {
                                    workflow: cw_str.to_owned(),
                                    reason: format!(
                                        "caller `{trig}` must not specify `paths` or `paths-ignore`"
                                    ),
                                });
                            }
                            if trig == "pull_request" {
                                if yaml_map_get(tmap, "branches-ignore").is_some() {
                                    return Err(TcbError::WorkflowValidation {
                                        workflow: cw_str.to_owned(),
                                        reason: "`pull_request` must not specify `branches-ignore`"
                                            .to_owned(),
                                    });
                                }
                                if let Some(brs) = yaml_map_get(tmap, "branches")
                                    .and_then(serde_yaml_ng::Value::as_sequence)
                                {
                                    let has_default = brs.iter().any(|v| {
                                        v.as_str() == Some(cfg.repo.default_branch.as_str())
                                    });
                                    if !has_default {
                                        return Err(TcbError::WorkflowValidation {
                                            workflow: cw_str.to_owned(),
                                            reason: format!(
                                                "`pull_request.branches` excludes default_branch `{}`",
                                                cfg.repo.default_branch
                                            ),
                                        });
                                    }
                                }
                            }
                        }
                    }
                    if triggers.contains("push") {
                        let push_branches_ok = yaml_map_get(on_map, "push")
                            .and_then(serde_yaml_ng::Value::as_mapping)
                            .and_then(|pm| yaml_map_get(pm, "branches"))
                            .and_then(serde_yaml_ng::Value::as_sequence)
                            .is_some_and(|seq| {
                                seq.len() == 1
                                    && seq[0].as_str() == Some(cfg.repo.default_branch.as_str())
                            });
                        if !push_branches_ok {
                            return Err(TcbError::WorkflowValidation {
                                workflow: cw_str.to_owned(),
                                reason: format!(
                                    "`push` trigger must restrict `branches: [{}]`",
                                    cfg.repo.default_branch
                                ),
                            });
                        }
                    }
                } else if triggers.contains("push") {
                    return Err(TcbError::WorkflowValidation {
                        workflow: cw_str.to_owned(),
                        reason: format!(
                            "`push` trigger must restrict `branches: [{}]`",
                            cfg.repo.default_branch
                        ),
                    });
                }

                let (job_key, jmap) = validate_single_caller_job(
                    &wf_map,
                    cw_str,
                    &["uses", "with", "permissions", "name"],
                )?;
                let display_name = match yaml_map_get(jmap, "name") {
                    Some(serde_yaml_ng::Value::String(s)) => s.as_str(),
                    None => job_key,
                    Some(_) => {
                        return Err(TcbError::WorkflowValidation {
                            workflow: cw_str.to_owned(),
                            reason: "caller job `name` must be a string".to_owned(),
                        });
                    }
                };
                if display_name.contains("${{") || display_name != expected_prefix {
                    return Err(TcbError::WorkflowValidation {
                        workflow: cw_str.to_owned(),
                        reason: format!(
                            "caller job display name `{display_name}` != expected `{expected_prefix}`"
                        ),
                    });
                }
                let uses_s = yaml_map_get(jmap, "uses")
                    .and_then(serde_yaml_ng::Value::as_str)
                    .ok_or_else(|| TcbError::WorkflowValidation {
                        workflow: cw_str.to_owned(),
                        reason: "caller job missing `uses`".to_owned(),
                    })?;
                let pr_only_caller = triggers.len() == 1 && triggers.contains("pull_request");
                let allowed_engine_uris: Vec<&str> = if pr_only_caller {
                    vec![
                        signer.trusted_engine_workflow.as_str(),
                        signer.trusted_pr_workflow.as_str(),
                    ]
                } else {
                    vec![signer.trusted_engine_workflow.as_str()]
                };
                validate_uses_pinned_to_trusted_sha(
                    uses_s,
                    &allowed_engine_uris,
                    &signer.trusted_engine_shas,
                    cw_str,
                )?;
                validate_engine_with_inputs(jmap, cw_str, false)?;
            }
            if !covered_triggers.contains("pull_request") || !covered_triggers.contains("push") {
                return Err(TcbError::WorkflowValidation {
                    workflow: ".github/workflows".to_owned(),
                    reason: "`caller_workflows` must cover both `pull_request` and `push`"
                        .to_owned(),
                });
            }
        }
        CallerMode::OrgRuleset {
            push_caller_workflow,
            ..
        } => {
            if let Some(pw) = push_caller_workflow {
                active_callers.insert(pw.clone());
                let wf_map = read_regular_100644_yaml(tree, pw)?;
                let pw_str = pw.as_str();
                forbid_cancel_in_progress(&wf_map, pw_str)?;
                let (triggers, on_map_opt) = extract_on_trigger_names(&wf_map, pw_str)?;
                if triggers.len() != 1 || !triggers.contains("push") {
                    return Err(TcbError::WorkflowValidation {
                        workflow: pw_str.to_owned(),
                        reason: "`push_caller_workflow` must declare strictly `on: push`"
                            .to_owned(),
                    });
                }
                let push_ok = on_map_opt
                    .as_ref()
                    .and_then(|om| yaml_map_get(om, "push"))
                    .and_then(serde_yaml_ng::Value::as_mapping)
                    .is_some_and(|pm| {
                        yaml_map_get(pm, "paths").is_none()
                            && yaml_map_get(pm, "paths-ignore").is_none()
                            && yaml_map_get(pm, "branches")
                                .and_then(serde_yaml_ng::Value::as_sequence)
                                .is_some_and(|seq| {
                                    seq.len() == 1
                                        && seq[0].as_str() == Some(cfg.repo.default_branch.as_str())
                                })
                    });
                if !push_ok {
                    return Err(TcbError::WorkflowValidation {
                        workflow: pw_str.to_owned(),
                        reason: format!(
                            "`push_caller_workflow` must restrict `branches: [{}]` with zero path filters",
                            cfg.repo.default_branch
                        ),
                    });
                }
                let (_jkey, jmap) = validate_single_caller_job(
                    &wf_map,
                    pw_str,
                    &["uses", "with", "permissions", "name"],
                )?;
                let uses_s = yaml_map_get(jmap, "uses")
                    .and_then(serde_yaml_ng::Value::as_str)
                    .ok_or_else(|| TcbError::WorkflowValidation {
                        workflow: pw_str.to_owned(),
                        reason: "missing `uses`".to_owned(),
                    })?;
                validate_uses_pinned_to_trusted_sha(
                    uses_s,
                    &[signer.trusted_engine_workflow.as_str()],
                    &signer.trusted_engine_shas,
                    pw_str,
                )?;
                validate_engine_with_inputs(jmap, pw_str, true)?;
            }
        }
    }

    // 2. Validate hoisted Stage-1 `review_signal_workflow` & Stage-2 `review_rerun_workflow`.
    active_callers.insert(cfg.tcb.review_signal_workflow.clone());
    active_callers.insert(cfg.tcb.review_rerun_workflow.clone());

    let sig_path_str = cfg.tcb.review_signal_workflow.as_str();
    let sig_map = read_regular_100644_yaml(tree, &cfg.tcb.review_signal_workflow)?;
    let sig_wf_name = yaml_map_get(&sig_map, "name")
        .and_then(serde_yaml_ng::Value::as_str)
        .filter(|s| !s.trim().is_empty() && !s.contains("${{"))
        .ok_or_else(|| TcbError::WorkflowValidation {
            workflow: sig_path_str.to_owned(),
            reason: "`review_signal_workflow` must declare a non-empty literal `name:`".to_owned(),
        })?
        .to_owned();
    let (sig_trigs, sig_on_map) = extract_on_trigger_names(&sig_map, sig_path_str)?;
    let sig_on_ok = sig_trigs.len() == 1
        && sig_trigs.contains("pull_request_review")
        && sig_on_map
            .as_ref()
            .and_then(|m| yaml_map_get(m, "pull_request_review"))
            .and_then(serde_yaml_ng::Value::as_mapping)
            .is_some_and(|prm| {
                prm.len() == 1
                    && yaml_map_get(prm, "types")
                        .and_then(serde_yaml_ng::Value::as_sequence)
                        .is_some_and(|seq| {
                            let set: BTreeSet<&str> = seq
                                .iter()
                                .filter_map(serde_yaml_ng::Value::as_str)
                                .collect();
                            seq.len() == 2 && set.contains("submitted") && set.contains("dismissed")
                        })
            });
    if !sig_on_ok {
        return Err(TcbError::WorkflowValidation {
            workflow: sig_path_str.to_owned(),
            reason: "`review_signal_workflow` must declare strictly `on: pull_request_review: { types: [submitted, dismissed] }`".to_owned(),
        });
    }
    let sig_perms_empty = yaml_map_get(&sig_map, "permissions")
        .and_then(serde_yaml_ng::Value::as_mapping)
        .is_some_and(serde_yaml_ng::Mapping::is_empty);
    if !sig_perms_empty {
        return Err(TcbError::WorkflowValidation {
            workflow: sig_path_str.to_owned(),
            reason: "`review_signal_workflow` must declare top-level `permissions: {}`".to_owned(),
        });
    }
    let (sig_jkey, sig_jmap) =
        validate_single_caller_job(&sig_map, sig_path_str, &["uses", "permissions", "name"])?;
    let sig_display = yaml_map_get(sig_jmap, "name")
        .and_then(serde_yaml_ng::Value::as_str)
        .unwrap_or(sig_jkey);
    if sig_display == gate_check_name
        || sig_display == "gate"
        || caller_prefix.is_some_and(|cp| sig_display == cp)
    {
        return Err(TcbError::WorkflowValidation {
            workflow: sig_path_str.to_owned(),
            reason: format!(
                "`review_signal_workflow` job `{sig_display}` collides with caller/gate check name"
            ),
        });
    }
    if let Some(jp) = yaml_map_get(sig_jmap, "permissions")
        && !jp
            .as_mapping()
            .is_some_and(serde_yaml_ng::Mapping::is_empty)
    {
        return Err(TcbError::WorkflowValidation {
            workflow: sig_path_str.to_owned(),
            reason: "`review_signal_workflow` job permissions must be `{}`".to_owned(),
        });
    }
    let sig_uses = yaml_map_get(sig_jmap, "uses")
        .and_then(serde_yaml_ng::Value::as_str)
        .ok_or_else(|| TcbError::WorkflowValidation {
            workflow: sig_path_str.to_owned(),
            reason: "missing `uses`".to_owned(),
        })?;
    validate_uses_pinned_to_trusted_sha(
        sig_uses,
        &[signer.trusted_review_signal_workflow.as_str()],
        &signer.trusted_engine_shas,
        sig_path_str,
    )?;

    let rr_path_str = cfg.tcb.review_rerun_workflow.as_str();
    let rr_map = read_regular_100644_yaml(tree, &cfg.tcb.review_rerun_workflow)?;
    let (rr_trigs, rr_on_map) = extract_on_trigger_names(&rr_map, rr_path_str)?;
    let rr_on_ok = rr_trigs.len() == 1
        && rr_trigs.contains("workflow_run")
        && rr_on_map
            .as_ref()
            .and_then(|m| yaml_map_get(m, "workflow_run"))
            .and_then(serde_yaml_ng::Value::as_mapping)
            .is_some_and(|wrm| {
                wrm.len() == 2
                    && yaml_map_get(wrm, "workflows")
                        .and_then(serde_yaml_ng::Value::as_sequence)
                        .is_some_and(|seq| {
                            seq.len() == 1 && seq[0].as_str() == Some(sig_wf_name.as_str())
                        })
                    && yaml_map_get(wrm, "types")
                        .and_then(serde_yaml_ng::Value::as_sequence)
                        .is_some_and(|seq| seq.len() == 1 && seq[0].as_str() == Some("completed"))
            });
    if !rr_on_ok {
        return Err(TcbError::WorkflowValidation {
            workflow: rr_path_str.to_owned(),
            reason: format!(
                "`review_rerun_workflow` must declare strictly `on: workflow_run: {{ workflows: [{sig_wf_name:?}], types: [completed] }}` with zero branch filters"
            ),
        });
    }
    let (rr_jkey, rr_jmap) = validate_single_caller_job(
        &rr_map,
        rr_path_str,
        &["uses", "with", "permissions", "name"],
    )?;
    let rr_display = yaml_map_get(rr_jmap, "name")
        .and_then(serde_yaml_ng::Value::as_str)
        .unwrap_or(rr_jkey);
    if rr_display == gate_check_name
        || rr_display == "gate"
        || caller_prefix.is_some_and(|cp| rr_display == cp)
    {
        return Err(TcbError::WorkflowValidation {
            workflow: rr_path_str.to_owned(),
            reason: format!(
                "`review_rerun_workflow` job `{rr_display}` collides with caller/gate check name"
            ),
        });
    }
    let rr_perms_map = yaml_map_get(rr_jmap, "permissions")
        .or_else(|| yaml_map_get(&rr_map, "permissions"))
        .and_then(serde_yaml_ng::Value::as_mapping)
        .ok_or_else(|| TcbError::WorkflowValidation {
            workflow: rr_path_str.to_owned(),
            reason: "`review_rerun_workflow` missing explicit permissions map".to_owned(),
        })?;
    let expected_rr_perms: BTreeMap<&str, &str> = BTreeMap::from([
        ("actions", "write"),
        ("contents", "read"),
        ("pull-requests", "read"),
    ]);
    let actual_rr_perms: BTreeMap<&str, &str> = rr_perms_map
        .iter()
        .filter_map(|(k, v)| Some((k.as_str()?, v.as_str()?)))
        .collect();
    if rr_perms_map.len() != 3 || actual_rr_perms != expected_rr_perms {
        return Err(TcbError::WorkflowValidation {
            workflow: rr_path_str.to_owned(),
            reason: "`review_rerun_workflow` must grant exact `permissions: { actions: write, contents: read, pull-requests: read }`".to_owned(),
        });
    }
    let rr_uses = yaml_map_get(rr_jmap, "uses")
        .and_then(serde_yaml_ng::Value::as_str)
        .ok_or_else(|| TcbError::WorkflowValidation {
            workflow: rr_path_str.to_owned(),
            reason: "missing `uses`".to_owned(),
        })?;
    validate_uses_pinned_to_trusted_sha(
        rr_uses,
        &[signer.trusted_review_rerun_workflow.as_str()],
        &signer.trusted_engine_shas,
        rr_path_str,
    )?;

    // 3. Validate every sibling `.github/workflows/*.{yml,yaml}` file.
    for path in tree.all_paths()? {
        let Some(rel) = path.as_str().strip_prefix(".github/workflows/") else {
            continue;
        };
        if rel.contains('/') || !(rel.ends_with(".yml") || rel.ends_with(".yaml")) {
            continue;
        }
        if active_callers.contains(&path) {
            continue;
        }
        let sib_map = read_regular_100644_yaml(tree, &path)?;
        let sib_str = path.as_str();
        let has_top_perms = if let Some(tp) = yaml_map_get(&sib_map, "permissions") {
            check_permissions_ceiling_for_sibling(tp, sib_str, "workflow")?;
            true
        } else {
            false
        };
        let Some(jobs_map) =
            yaml_map_get(&sib_map, "jobs").and_then(serde_yaml_ng::Value::as_mapping)
        else {
            return Err(TcbError::WorkflowValidation {
                workflow: sib_str.to_owned(),
                reason: "sibling workflow missing `jobs:` mapping".to_owned(),
            });
        };
        validate_sibling_jobs_anti_spoof(
            sib_str,
            jobs_map,
            has_top_perms,
            gate_check_name,
            caller_prefix,
        )?;
    }

    Ok(())
}

fn is_safe_non_tcb_workflow_in_tree(
    tree: &dyn SourceTree,
    path: &RepoRelPath,
    cfg: &ChecksConfig,
) -> bool {
    let Ok(wf_map) = read_regular_100644_yaml(tree, path) else {
        return false;
    };
    let Ok((trigs, _)) = extract_on_trigger_names(&wf_map, path.as_str()) else {
        return false;
    };
    if trigs.iter().any(|t| {
        matches!(
            t.as_str(),
            "pull_request_target" | "merge_group" | "workflow_run"
        )
    }) {
        return false;
    }
    let has_top_perms = match yaml_map_get(&wf_map, "permissions") {
        Some(tp) => check_non_tcb_workflow_permissions(tp),
        None => false,
    };
    let Some(jobs_map) = yaml_map_get(&wf_map, "jobs").and_then(serde_yaml_ng::Value::as_mapping)
    else {
        return false;
    };
    for jval in jobs_map.values() {
        let Some(jmap) = jval.as_mapping() else {
            return false;
        };
        match yaml_map_get(jmap, "permissions") {
            Some(jp) => {
                if !check_non_tcb_workflow_permissions(jp) {
                    return false;
                }
            }
            None if !has_top_perms => return false,
            None => {}
        }
    }
    validate_sibling_jobs_anti_spoof(
        path.as_str(),
        jobs_map,
        has_top_perms,
        cfg.tcb.caller.gate_check_name(),
        cfg.tcb.caller.caller_prefix(),
    )
    .is_ok()
}

/// Computes `EffectiveTcb(cfg, T_set)` across a non-empty set of trees `trees`,
/// classifying all paths in `T_union` (and arbitrary query paths via
/// `classify(&path)`) into `PathTrustClass::{Untrusted < DataPin < ExecutableTcb}`.
#[derive(Debug, Clone)]
pub struct EffectiveTcbMap {
    executable_paths: BTreeSet<RepoRelPath>,
    executable_subtrees: Vec<RepoRelPath>,
    valid_data_pins: BTreeSet<RepoRelPath>,
    safe_non_tcb_workflows: BTreeSet<RepoRelPath>,
    non_tcb_subtrees: Vec<RepoRelPath>,
}

impl EffectiveTcbMap {
    /// Classifies `path` under this `EffectiveTcb` map.
    pub fn classify(&self, path: &RepoRelPath) -> PathTrustClass {
        if self.executable_paths.contains(path)
            || self
                .executable_subtrees
                .iter()
                .any(|d| d.is_prefix_of(path))
        {
            return PathTrustClass::ExecutableTcb;
        }
        let s = path.as_str();
        if s == "CODEOWNERS"
            || s == "docs/CODEOWNERS"
            || s == ".github/CODEOWNERS"
            || s.starts_with(".github/actions/")
        {
            return PathTrustClass::ExecutableTcb;
        }
        if s.starts_with(".github/workflows/") {
            if self.safe_non_tcb_workflows.contains(path) {
                return PathTrustClass::Untrusted;
            }
            return PathTrustClass::ExecutableTcb;
        }
        let fname = path.file_name();
        let is_cargo_or_toolchain = matches!(fname, "rust-toolchain" | "rust-toolchain.toml")
            || s == ".cargo/config"
            || s == ".cargo/config.toml"
            || s.ends_with("/.cargo/config")
            || s.ends_with("/.cargo/config.toml");
        if is_cargo_or_toolchain && !is_under_non_tcb_subtree(path, &self.non_tcb_subtrees) {
            return PathTrustClass::ExecutableTcb;
        }
        if self.valid_data_pins.contains(path) {
            return PathTrustClass::DataPin;
        }
        PathTrustClass::Untrusted
    }

    /// Returns all known concrete `ExecutableTcb` paths in `T_union`.
    pub fn executable_paths(&self) -> &BTreeSet<RepoRelPath> {
        &self.executable_paths
    }
}

/// Evaluates `EffectiveTcb(cfg, T_set)` over `trees` (`pin_validation_tree`
/// selects the target tree in which `[pins.*].path` values are validated).
pub fn compute_effective_tcb(
    cfg: &ChecksConfig,
    config_path: &RepoRelPath,
    trees: &[&dyn SourceTree],
    pin_validation_tree: &dyn SourceTree,
) -> Result<EffectiveTcbMap, TcbError> {
    let mut t_union: BTreeSet<RepoRelPath> = BTreeSet::new();
    for t in trees {
        for p in t.all_paths()? {
            t_union.insert(p);
        }
    }

    let github_dir = RepoRelPath::new(".github").expect("static");
    let gh_actions = RepoRelPath::new(".github/actions").expect("static");
    let gh_workflows = RepoRelPath::new(".github/workflows").expect("static");
    let gh_codeowners = RepoRelPath::new(".github/CODEOWNERS").expect("static");
    let root_codeowners = RepoRelPath::new("CODEOWNERS").expect("static");
    let docs_codeowners = RepoRelPath::new("docs/CODEOWNERS").expect("static");

    // 1. Enforce zero-symlink invariant across all core TCB paths, prefixes,
    // `non_tcb_subtrees`, and `workdirs` in every `T ∈ trees`.
    for t in trees {
        ensure_no_symlink_at_or_ancestors(*t, config_path, true)?;
        ensure_no_symlink_at_or_ancestors(*t, &gh_codeowners, true)?;
        ensure_no_symlink_at_or_ancestors(*t, &root_codeowners, true)?;
        if t.kind_of(&docs_codeowners)?.is_some() {
            ensure_no_symlink_at_or_ancestors(*t, &docs_codeowners, true)?;
        }
        if t.kind_of(&github_dir)? == Some(EntryKind::Symlink) {
            return Err(TcbError::SymlinkViolation(github_dir.clone()));
        }
        if t.kind_of(&gh_actions)? == Some(EntryKind::Symlink) {
            return Err(TcbError::SymlinkViolation(gh_actions.clone()));
        }
        if t.kind_of(&gh_workflows)? == Some(EntryKind::Symlink) {
            return Err(TcbError::SymlinkViolation(gh_workflows.clone()));
        }
        for sub in &cfg.tcb.non_tcb_subtrees {
            ensure_no_symlink_at_or_ancestors(*t, sub, true)?;
        }
        for chk in cfg.checks.values() {
            if let Some(ref wd) = chk.workdir {
                ensure_no_symlink_at_or_ancestors(*t, wd, true)?;
            }
        }
        for ispec in cfg.images.values() {
            ensure_no_symlink_at_or_ancestors(*t, &ispec.dockerfile, true)?;
        }
        for pspec in cfg.pins.values() {
            ensure_no_symlink_at_or_ancestors(*t, &pspec.path, true)?;
        }
    }

    let mut executable_paths: BTreeSet<RepoRelPath> = BTreeSet::new();
    let mut executable_subtrees: Vec<RepoRelPath> = Vec::new();
    executable_paths.insert(config_path.clone());
    executable_paths.insert(gh_codeowners);
    executable_paths.insert(root_codeowners);
    executable_paths.insert(docs_codeowners);
    executable_subtrees.push(gh_actions);
    for ispec in cfg.images.values() {
        executable_paths.insert(ispec.dockerfile.clone());
    }

    // Check `.github/actions/**` and active `**/.cargo` / `rust-toolchain*` +
    // recursive Cargo `include`s across every `T ∈ trees`.
    for p in &t_union {
        let s = p.as_str();
        if s.starts_with(".github/actions/") {
            for t in trees {
                ensure_no_symlink_at_or_ancestors(*t, p, true)?;
            }
            executable_paths.insert(p.clone());
        }
        if s.starts_with(".github/workflows/")
            && !cfg.tcb.non_tcb_workflows.iter().any(|b| {
                matches!(&cfg.tcb.caller, CallerMode::RepoRuleset { .. })
                    && s == format!(".github/workflows/{b}")
            })
        {
            for t in trees {
                ensure_no_symlink_at_or_ancestors(*t, p, true)?;
            }
            executable_paths.insert(p.clone());
        }

        let fname = p.file_name();
        // Reject any leaf symlink at `.cargo` or `**/.cargo` outside
        // `non_tcb_subtrees` even when no literal `.cargo/config(.toml)` child
        // path appears under `lstat` traversal.
        if fname == ".cargo" && !is_under_non_tcb_subtree(p, &cfg.tcb.non_tcb_subtrees) {
            for t in trees {
                ensure_no_symlink_at_or_ancestors(*t, p, true)?;
            }
            executable_paths.insert(p.clone());
        }
        let is_cargo_cfg = s == ".cargo/config"
            || s == ".cargo/config.toml"
            || s.ends_with("/.cargo/config")
            || s.ends_with("/.cargo/config.toml");
        let is_toolchain = matches!(fname, "rust-toolchain" | "rust-toolchain.toml");

        if (is_cargo_cfg || is_toolchain) && !is_under_non_tcb_subtree(p, &cfg.tcb.non_tcb_subtrees)
        {
            for t in trees {
                ensure_no_symlink_at_or_ancestors(*t, p, true)?;
            }
            executable_paths.insert(p.clone());
            if is_cargo_cfg {
                // Walk recursive Cargo 1.82+ `include`s in every tree where this
                // `.cargo/config(.toml)` directory exists; classify all resolved
                // targets (even absent `optional = true` targets and targets
                // inside `non_tcb_subtrees`) as `ExecutableTcb`.
                let cfg_dir = p.parent().and_then(|c| c.parent());
                for t in trees {
                    if t.kind_of(p)?.is_some() {
                        let discovered = discover_cargo_configs_from_dir(*t, cfg_dir.as_ref())
                            .map_err(|e| TcbError::CargoConfig(e.to_string()))?;
                        for inc in discovered {
                            for t_inner in trees {
                                ensure_no_symlink_at_or_ancestors(*t_inner, &inc.path, true)?;
                            }
                            executable_paths.insert(inc.path);
                        }
                    }
                }
            }
        }
    }

    // Safe Non-TCB Workflow Validation across ALL `T ∈ trees`.
    let mut safe_non_tcb_workflows = BTreeSet::new();
    if matches!(&cfg.tcb.caller, CallerMode::RepoRuleset { .. }) {
        for base in &cfg.tcb.non_tcb_workflows {
            let wf_path = RepoRelPath::new(&format!(".github/workflows/{base}"))?;
            let mut safe_everywhere = true;
            for t in trees {
                if t.kind_of(&wf_path)?.is_some()
                    && !is_safe_non_tcb_workflow_in_tree(*t, &wf_path, cfg)
                {
                    safe_everywhere = false;
                    break;
                }
            }
            if safe_everywhere {
                safe_non_tcb_workflows.insert(wf_path);
            } else {
                executable_paths.insert(wf_path);
            }
        }
    }

    // Transitive Target & Directory-Subtree Folding for `[images.*].context`
    // and `extra_executable_paths` across `T_union`.
    let extra_set = compile_selector_globset(&cfg.tcb.extra_executable_paths)?;

    let mut seed_exec_paths: BTreeSet<RepoRelPath> = BTreeSet::new();
    for p in &t_union {
        if extra_set.is_match(p.as_str()) {
            seed_exec_paths.insert(p.clone());
        }
    }
    for t in trees {
        let t_paths = t.all_paths()?;
        for ispec in cfg.images.values() {
            let mut present_selectors = Vec::with_capacity(ispec.context.len());
            for sel in &ispec.context {
                match sel {
                    InputSelector::Glob { .. } => present_selectors.push(sel.clone()),
                    InputSelector::CargoWorkspace { manifest_path, .. } => {
                        ensure_no_symlink_at_or_ancestors(*t, manifest_path, true)?;
                        if t.kind_of(manifest_path)?.is_some() {
                            present_selectors.push(sel.clone());
                        }
                    }
                }
            }
            let (ctx, _) = expand_selectors_in_tree(*t, &present_selectors, &t_paths, None)
                .map_err(|e| TcbError::CargoConfig(e.to_string()))?;
            seed_exec_paths.extend(ctx);
        }
    }

    let mut worklist: Vec<RepoRelPath> = seed_exec_paths.into_iter().collect();
    let mut visited_fold: BTreeSet<RepoRelPath> = BTreeSet::new();
    while let Some(item) = worklist.pop() {
        if !visited_fold.insert(item.clone()) {
            continue;
        }
        executable_paths.insert(item.clone());
        for t in trees {
            if matches!(t.entry(&item)?, Some(TreeEntry::Symlink { .. })) {
                let (hops, final_q, final_kind) = resolve_in_tree(*t, &item)?;
                for h in hops {
                    executable_paths.insert(h.clone());
                    worklist.push(h);
                }
                executable_paths.insert(final_q.clone());
                if final_kind == Some(EntryKind::Dir) {
                    if !executable_subtrees.contains(&final_q) {
                        executable_subtrees.push(final_q.clone());
                    }
                    for tp in &t_union {
                        if final_q.is_prefix_of(tp) {
                            worklist.push(tp.clone());
                        }
                    }
                } else {
                    worklist.push(final_q);
                }
            }
        }
    }

    // `DataPin` validation in `pin_validation_tree`: any pin that fails
    // validation (or collides with `ExecutableTcb`) escalates to `ExecutableTcb`.
    let mut valid_data_pins = BTreeSet::new();
    for (pin_id, pspec) in &cfg.pins {
        let already_exec = executable_paths.contains(&pspec.path)
            || executable_subtrees
                .iter()
                .any(|d| d.is_prefix_of(&pspec.path));
        if already_exec {
            executable_paths.insert(pspec.path.clone());
            continue;
        }
        if pin_validation_tree.kind_of(&pspec.path)?.is_none() {
            // Deleting a pin file escalates to `ExecutableTcb`.
            executable_paths.insert(pspec.path.clone());
        } else if cfg.evaluate_pin(pin_validation_tree, pin_id).is_ok() {
            valid_data_pins.insert(pspec.path.clone());
        } else {
            executable_paths.insert(pspec.path.clone());
        }
    }

    Ok(EffectiveTcbMap {
        executable_paths,
        executable_subtrees,
        valid_data_pins,
        safe_non_tcb_workflows,
        non_tcb_subtrees: cfg.tcb.non_tcb_subtrees.clone(),
    })
}

/// Lattice join `⊔_{c ∈ configs} EffectiveTcb(c, trees)`.
pub fn classify_under_joined_tcb(maps: &[EffectiveTcbMap], path: &RepoRelPath) -> PathTrustClass {
    maps.iter().fold(PathTrustClass::Untrusted, |acc, m| {
        acc.join(m.classify(path))
    })
}

#[derive(Debug, Clone)]
enum CodeownersMatcher {
    Always,
    RootFileOnly,
    Globs(GlobSet),
}

impl CodeownersMatcher {
    fn compile(pattern: &str) -> Result<Self, TcbError> {
        if matches!(pattern, "*" | "**" | "/**" | "/") {
            return Ok(Self::Always);
        }
        // Root-only `"/*"` matches ONLY root-level files `/<file>` with zero `/`
        // in `<file>` (confirmed via live GitHub `/codeowners/errors` & CODEOWNERS rules).
        if pattern == "/*" {
            return Ok(Self::RootFileOnly);
        }

        let add_glob = |b: &mut GlobSetBuilder, g: &str| -> Result<(), TcbError> {
            let parsed = GlobBuilder::new(g)
                .literal_separator(true)
                .backslash_escape(false)
                .build()
                .map_err(|e| {
                    TcbError::CodeownersValidation(format!(
                        "invalid CODEOWNERS glob `{pattern}`: {e}"
                    ))
                })?;
            b.add(parsed);
            Ok(())
        };

        let mut builder = GlobSetBuilder::new();
        // Trailing `/` in CODEOWNERS matches everything recursively inside that dir.
        if let Some(dir_pat) = pattern.strip_suffix('/') {
            if let Some(anchored_dir) = dir_pat.strip_prefix('/') {
                if anchored_dir.is_empty() {
                    return Ok(Self::Always);
                }
                add_glob(&mut builder, &format!("{anchored_dir}/**"))?;
            } else {
                add_glob(&mut builder, &format!("{dir_pat}/**"))?;
                add_glob(&mut builder, &format!("**/{dir_pat}/**"))?;
            }
        } else if let Some(anchored) = pattern.strip_prefix('/') {
            add_glob(&mut builder, anchored)?;
            if !anchored.contains('*') && !anchored.contains('?') {
                add_glob(&mut builder, &format!("{anchored}/**"))?;
            }
        } else if pattern.contains('/') {
            // Contains inner `/` without leading `/`: gitignore anchors it to root!
            add_glob(&mut builder, pattern)?;
        } else {
            // Basename pattern (`*.yml`, `Cargo.toml`): matches at any depth!
            add_glob(&mut builder, pattern)?;
            add_glob(&mut builder, &format!("**/{pattern}"))?;
        }

        let set = builder.build().map_err(|e| {
            TcbError::CodeownersValidation(format!("CODEOWNERS globset `{pattern}`: {e}"))
        })?;
        Ok(Self::Globs(set))
    }

    fn matches_rooted(&self, rooted_path: &str) -> bool {
        debug_assert!(rooted_path.starts_with('/'));
        let rel = &rooted_path[1..];
        match self {
            Self::Always => true,
            Self::RootFileOnly => !rel.is_empty() && !rel.contains('/'),
            Self::Globs(set) => set.is_match(rel),
        }
    }
}

#[derive(Debug, Clone)]
struct CodeownersRule {
    pattern: String,
    matcher: CodeownersMatcher,
    owners: Vec<CodeOwnerPrincipal>,
}

fn materialize_glob_probe_path(glob_str: &str) -> Option<RepoRelPath> {
    let replaced = glob_str
        .replace("/**", "/__probe__")
        .replace("**/", "__probe__/")
        .replace("**", "__probe__")
        .replace('*', "probe")
        .replace('?', "p");
    RepoRelPath::new(&replaced).ok()
}

/// Validates `.github/CODEOWNERS` statically (`§4.2` + Obligation `O5` flat `\`
/// ban + recursive `/.github/**` dominance + last-match-wins simulation across
/// tracked and synthetic probe paths).
pub fn validate_codeowners(
    tree: &dyn SourceTree,
    cfg: &ChecksConfig,
    config_path: &RepoRelPath,
) -> Result<(), TcbError> {
    let CallerMode::RepoRuleset { ref codeowners, .. } = cfg.tcb.caller else {
        return Ok(());
    };
    let expected_owners: BTreeSet<&CodeOwnerPrincipal> = codeowners.iter().collect();

    let root_co = RepoRelPath::new("CODEOWNERS").expect("static");
    let docs_co = RepoRelPath::new("docs/CODEOWNERS").expect("static");
    if tree.kind_of(&root_co)?.is_some() {
        return Err(TcbError::CodeownersValidation(
            "shadowing `/CODEOWNERS` must not exist".to_owned(),
        ));
    }
    if tree.kind_of(&docs_co)?.is_some() {
        return Err(TcbError::CodeownersValidation(
            "shadowing `/docs/CODEOWNERS` must not exist".to_owned(),
        ));
    }

    let co_path = RepoRelPath::new(".github/CODEOWNERS").expect("static");
    ensure_no_symlink_at_or_ancestors(tree, &co_path, true)?;
    let Some(TreeEntry::Regular { executable }) = tree.entry(&co_path)? else {
        return Err(TcbError::CodeownersValidation(
            "`.github/CODEOWNERS` must exist as a regular non-symlink file".to_owned(),
        ));
    };
    if executable {
        return Err(TcbError::CodeownersValidation(
            "`.github/CODEOWNERS` must be mode 100644 (non-executable)".to_owned(),
        ));
    }
    let bytes = tree.read_blob(&co_path)?;
    if bytes.len() >= MAX_CODEOWNERS_BYTES {
        return Err(TcbError::CodeownersValidation(format!(
            "`.github/CODEOWNERS` size {} >= 3,000,000 byte GitHub limit",
            bytes.len()
        )));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| TcbError::CodeownersValidation(format!("invalid UTF-8: {e}")))?;

    let mut rules: Vec<CodeownersRule> = Vec::new();
    for (lineno, raw_line) in text.lines().enumerate() {
        let line_num = lineno + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Strip inline `#` comment ONLY after Checking for `\` first!
        // Obligation `O5`: flat ban on ANY `\` character in CODEOWNERS rule lines
        // (blocking trailing `\`, `\#`, and `/\.github/...` backslash escapes).
        let before_comment = trimmed.split('#').next().unwrap_or("").trim();
        if raw_line.split('#').next().unwrap_or("").contains('\\') || trimmed.contains("\\#") {
            return Err(TcbError::CodeownersValidation(format!(
                "line {line_num}: backslash `\\` characters are forbidden in `.github/CODEOWNERS`"
            )));
        }
        let mut tokens = before_comment.split_whitespace();
        let Some(pattern) = tokens.next() else {
            continue;
        };
        if pattern.starts_with('!')
            || pattern.contains('[')
            || pattern.contains(']')
            || pattern.contains('{')
            || pattern.contains('}')
        {
            return Err(TcbError::CodeownersValidation(format!(
                "line {line_num}: `!` negation, `[...]` classes, and `{{...}}` braces are forbidden (`{pattern}`)"
            )));
        }
        let owner_tokens: Vec<&str> = tokens.collect();
        if owner_tokens.is_empty() {
            return Err(TcbError::CodeownersValidation(format!(
                "line {line_num}: pattern `{pattern}` has an empty owner list (strips ownership)"
            )));
        }
        let mut parsed_owners = Vec::with_capacity(owner_tokens.len());
        for otok in owner_tokens {
            let principal = CodeOwnerPrincipal::new(otok).map_err(|_| {
                TcbError::CodeownersValidation(format!(
                    "line {line_num}: invalid CODEOWNERS principal `{otok}` (only `@user` or `@org/team` allowed)"
                ))
            })?;
            parsed_owners.push(principal);
        }
        let matcher = CodeownersMatcher::compile(pattern)?;
        rules.push(CodeownersRule {
            pattern: pattern.to_owned(),
            matcher,
            owners: parsed_owners,
        });
    }

    // Universal Recursive `/.github/**` Dominance:
    // Find at least one `R_k` with `pattern ∈ {"*", "**", "/**", "/.github/", "/.github/**"}`
    // and `R_k.owners ⊆ expected_owners` such that every subsequent `R_m` (`m > k`)
    // with `R_m.owners ⊈ expected_owners` is syntactically disjoint from `/.github/**`.
    let mut github_dominance_ok = false;
    for (k, rk) in rules.iter().enumerate() {
        let is_recursive_github = matches!(
            rk.pattern.as_str(),
            "*" | "**" | "/**" | "/.github/" | "/.github/**"
        );
        if !is_recursive_github {
            continue;
        }
        if !rk.owners.iter().all(|o| expected_owners.contains(o)) {
            continue;
        }
        let mut subsequent_disjoint = true;
        for rm in &rules[k + 1..] {
            if rm.owners.iter().all(|o| expected_owners.contains(o)) {
                continue;
            }
            let pat = rm.pattern.as_str();
            if !pat.starts_with('/') || pat.starts_with("//") {
                subsequent_disjoint = false;
                break;
            }
            let segs: Vec<&str> = pat[1..].trim_end_matches('/').split('/').collect();
            if segs.is_empty() || segs.iter().any(|s| s.is_empty() || *s == "." || *s == "..") {
                subsequent_disjoint = false;
                break;
            }
            let seg1 = segs[0];
            if seg1 == ".github" || seg1.contains('*') || seg1.contains('?') {
                subsequent_disjoint = false;
                break;
            }
        }
        if subsequent_disjoint {
            github_dominance_ok = true;
            break;
        }
    }
    if !github_dominance_ok {
        return Err(TcbError::CodeownersValidation(
            "`.github/CODEOWNERS` lacks an unoverridden recursive `/.github/**` catch-all owned by `tcb.caller.codeowners`".to_owned(),
        ));
    }

    // Build tracked + synthetic probe path set for last-match-wins simulation.
    let eff_tcb = compute_effective_tcb(cfg, config_path, &[tree], tree)?;
    let mut probe_paths: BTreeSet<RepoRelPath> = BTreeSet::new();
    for tp in tree.all_paths()? {
        if tp.as_str().starts_with(".github/") || eff_tcb.classify(&tp) != PathTrustClass::Untrusted
        {
            probe_paths.insert(tp);
        }
    }

    for static_probe in [
        ".github/CODEOWNERS",
        ".github/__probe__",
        ".github/actions/__probe__/action.yml",
        ".github/actions/probe/sub/helper.sh",
        ".github/workflows/__probe__.yml",
        ".github/workflows/__probe__.yaml",
        ".github/workflows/probe.yml",
        ".github/workflows/probe.yaml",
        ".cargo/config",
        ".cargo/config.toml",
        "rust-toolchain",
        "rust-toolchain.toml",
        "__probe__/.cargo/config",
        "__probe__/.cargo/config.toml",
        "__probe__/rust-toolchain",
        "__probe__/rust-toolchain.toml",
        "__a__/__b__/.cargo/config",
        "__a__/__b__/.cargo/config.toml",
        "__a__/__b__/rust-toolchain",
        "__a__/__b__/rust-toolchain.toml",
    ] {
        let p = RepoRelPath::new(static_probe).expect("static probe path");
        if !is_under_non_tcb_subtree(&p, &cfg.tcb.non_tcb_subtrees) {
            probe_paths.insert(p);
        }
    }
    probe_paths.insert(config_path.clone());
    for ispec in cfg.images.values() {
        probe_paths.insert(ispec.dockerfile.clone());
        for sel in &ispec.context {
            if let InputSelector::Glob { include, .. } = sel {
                for g in include {
                    if let Some(mp) = materialize_glob_probe_path(g) {
                        probe_paths.insert(mp);
                    }
                }
            }
        }
    }
    for pspec in cfg.pins.values() {
        probe_paths.insert(pspec.path.clone());
    }
    for g in &cfg.tcb.extra_executable_paths {
        if let Some(mp) = materialize_glob_probe_path(g) {
            probe_paths.insert(mp);
        }
    }

    for p in &probe_paths {
        let rooted = format!("/{}", p.as_str());
        let winning = rules.iter().rfind(|r| r.matcher.matches_rooted(&rooted));
        let Some(win_rule) = winning else {
            return Err(TcbError::CodeownersValidation(format!(
                "path `{rooted}` is unowned under `.github/CODEOWNERS`"
            )));
        };
        if win_rule.owners.is_empty()
            || !win_rule.owners.iter().all(|o| expected_owners.contains(o))
        {
            return Err(TcbError::CodeownersValidation(format!(
                "path `{rooted}` matched rule `{}` with owners outside `tcb.caller.codeowners`",
                win_rule.pattern
            )));
        }
    }

    Ok(())
}

/// Evaluates owner PR approval (`§4.3` + Obligation `O1`: projects
/// `COMMENTED` `/ci-core approve <oid>` and `/ci-core unapprove` reviews
/// **independently of `pr_head_sha` first** before selecting each owner's
/// globally latest effective review, blocking `C1 -> C2 -> C1` force-push-back
/// resurrection).
pub fn is_owner_approved(
    reviews: &[PrReview],
    owner_ids: &[u64],
    allow_self_approval: bool,
    pr_head_sha: &GitOid,
) -> bool {
    let owner_set: BTreeSet<u64> = owner_ids.iter().copied().collect();
    type OwnerLatestVerdict = ((crate::types::UnixSecs, u64), PrReviewState, Option<GitOid>);
    // Map `uid -> ((submitted_at, review_id), effective_state, effective_commit_id)`
    let mut latest_by_owner: BTreeMap<u64, OwnerLatestVerdict> = BTreeMap::new();

    for r in reviews {
        if !owner_set.contains(&r.user_id) {
            continue;
        }
        let projected: Option<(PrReviewState, Option<GitOid>)> = match r.state {
            PrReviewState::Approved
            | PrReviewState::ChangesRequested
            | PrReviewState::Dismissed => Some((r.state, r.commit_id)),
            PrReviewState::Pending => None,
            PrReviewState::Commented => {
                if allow_self_approval {
                    let trimmed = r.body.trim();
                    if let Some(oid_str) = trimmed.strip_prefix("/ci-core approve ") {
                        if let Ok(oid) = GitOid::from_hex(oid_str.trim()) {
                            if r.commit_id == Some(oid) {
                                Some((PrReviewState::Approved, Some(oid)))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else if trimmed == "/ci-core unapprove" {
                        Some((PrReviewState::Dismissed, r.commit_id))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };

        let Some((eff_state, eff_commit)) = projected else {
            continue;
        };
        let order_key = (r.submitted_at, r.review_id);
        let replace = match latest_by_owner.get(&r.user_id) {
            None => true,
            Some((prev_key, _, _)) => order_key > *prev_key,
        };
        if replace {
            latest_by_owner.insert(r.user_id, (order_key, eff_state, eff_commit));
        }
    }

    let has_veto = latest_by_owner
        .values()
        .any(|(_, st, _)| *st == PrReviewState::ChangesRequested);
    if has_veto {
        return false;
    }

    latest_by_owner
        .values()
        .any(|(_, st, cid)| *st == PrReviewState::Approved && cid.as_ref() == Some(pr_head_sha))
}

/// Stage-2 `review-rerun` relevance filter (`§6.4` + Obligation `O1b`):
/// recognizes `DISMISSED` reviews (even from removed owners) plus any
/// `APPROVED`, `CHANGES_REQUESTED`, or `/ci-core {approve,unapprove}` review
/// from `owner_ids` unconditionally regardless of `allow_owner_self_approval`.
pub fn has_relevant_review_for_stage2(reviews: &[PrReview], owner_ids: &[u64]) -> bool {
    let owner_set: BTreeSet<u64> = owner_ids.iter().copied().collect();
    reviews.iter().any(|r| {
        if r.state == PrReviewState::Dismissed {
            return true;
        }
        if !owner_set.contains(&r.user_id) {
            return false;
        }
        match r.state {
            PrReviewState::Approved | PrReviewState::ChangesRequested => true,
            PrReviewState::Commented => {
                let t = r.body.trim();
                t.starts_with("/ci-core approve ") || t == "/ci-core unapprove"
            }
            PrReviewState::Dismissed | PrReviewState::Pending => false,
        }
    })
}

/// Pure `SourceTree`-free caller check against `CallerMode`.
pub fn caller_allowed(
    caller: &CallerMode,
    runtime_event: TriggerEvent,
    observed_run: &WorkflowRunMeta,
) -> bool {
    match caller {
        CallerMode::RepoRuleset {
            caller_workflows, ..
        } => {
            !observed_run.is_org_required_workflow
                && RepoRelPath::new(&observed_run.path).is_ok_and(|p| caller_workflows.contains(&p))
        }
        CallerMode::OrgRuleset {
            required_workflow_ids,
            push_caller_workflow,
            ..
        } => {
            if runtime_event == TriggerEvent::Push {
                !observed_run.is_org_required_workflow
                    && push_caller_workflow
                        .as_ref()
                        .is_some_and(|pw| pw.as_str() == observed_run.path)
            } else {
                observed_run.is_org_required_workflow
                    && required_workflow_ids.contains(&observed_run.workflow_id)
            }
        }
    }
}

/// Evaluates caller authorization accounting for an owner-approved
/// `ControlPlaneTransition` caller cutover (`tr.base.caller` or `eff_caller`).
pub fn caller_allowed_effective(
    eff_caller: &CallerMode,
    tcb_plan: &TcbPlan,
    runtime_event: TriggerEvent,
    observed_run: &WorkflowRunMeta,
) -> bool {
    if caller_allowed(eff_caller, runtime_event, observed_run) {
        return true;
    }
    if let TcbPlan::RequiresOwnerApproval {
        control_plane_transition: Some(tr),
        ..
    } = tcb_plan
    {
        return caller_allowed(&tr.base().caller, runtime_event, observed_run);
    }
    false
}

/// Resolves the active `ControlPlanePolicy` (`eff_cp`) from fresh `live_cfg`
/// (`H_default`) and `tcb_plan`.
pub fn resolve_effective_control_plane(
    live_cfg: &ChecksConfig,
    tcb_plan: &TcbPlan,
) -> Result<ControlPlanePolicy, TcbError> {
    let live_cp = live_cfg.control_plane();
    match tcb_plan {
        TcbPlan::Blocked { .. } => Err(TcbError::ControlPlaneRejected(
            "TcbPlan::Blocked cannot resolve an executable control plane".to_owned(),
        )),
        TcbPlan::NotRequired
        | TcbPlan::RequiresOwnerApproval {
            control_plane_transition: None,
            ..
        } => Ok(live_cp),
        TcbPlan::RequiresOwnerApproval {
            control_plane_transition: Some(tr),
            ..
        } => {
            if &live_cp != tr.base() && &live_cp != tr.candidate() {
                return Err(TcbError::ControlPlaneRejected(
                    "live default_branch control plane diverged from both transition base and candidate".to_owned(),
                ));
            }
            Ok(tr.candidate().clone())
        }
    }
}

/// Verifies runtime `referenced_workflows` pinning (`§3.3.3`):
/// `!W_refs.is_empty()`, every matching call uses exact `@<40-hex-sha>` with
/// `ref_str` absent or equal to `<sha>`, `sha ∈ policy.trusted_engine_shas`,
/// `|{ rw.workflow_uri_prefix() }| == 1`, and `|{ rw.sha }| == 1` (blocking
/// dual `@S_good` + `@S_revoked` calls). Accepts `trusted_pr_workflow` strictly
/// when `runtime_event == TriggerEvent::PullRequest`.
pub fn verify_engine_workflows(
    observed_workflows: &[ReferencedWorkflow],
    policy: &SignerPolicy,
    runtime_event: TriggerEvent,
) -> Result<GitOid, TcbError> {
    let allowed_uris: Vec<&str> = match runtime_event {
        TriggerEvent::PullRequest => vec![
            policy.trusted_engine_workflow.as_str(),
            policy.trusted_pr_workflow.as_str(),
        ],
        TriggerEvent::MergeGroup | TriggerEvent::Push => {
            vec![policy.trusted_engine_workflow.as_str()]
        }
    };
    let matching: Vec<(&str, &ReferencedWorkflow)> = observed_workflows
        .iter()
        .filter_map(|rw| {
            let pfx = rw.workflow_uri_prefix()?;
            allowed_uris.contains(&pfx).then_some((pfx, rw))
        })
        .collect();
    if matching.is_empty() {
        return Err(TcbError::EngineWorkflowPin(format!(
            "no referenced_workflows entry matched {allowed_uris:?}"
        )));
    }
    let mut distinct_uris: BTreeSet<&str> = BTreeSet::new();
    let mut distinct_shas: BTreeSet<GitOid> = BTreeSet::new();
    for (matched_uri, rw) in matching {
        let expected_path = format!("{matched_uri}@{}", rw.sha);
        if rw.path != expected_path {
            return Err(TcbError::EngineWorkflowPin(format!(
                "referenced workflow `{}` is not pinned by exact `@<40-hex-sha>`",
                rw.path
            )));
        }
        if let Some(ref rstr) = rw.ref_str
            && rstr != &rw.sha.to_hex()
        {
            return Err(TcbError::EngineWorkflowPin(format!(
                "referenced workflow carries mutable ref `{rstr}`"
            )));
        }
        if !policy.trusted_engine_shas.contains(&rw.sha) {
            return Err(TcbError::EngineWorkflowPin(format!(
                "referenced workflow SHA `{}` is not in trusted_engine_shas",
                rw.sha
            )));
        }
        distinct_uris.insert(matched_uri);
        distinct_shas.insert(rw.sha);
    }
    if distinct_uris.len() != 1 || distinct_shas.len() != 1 {
        return Err(TcbError::EngineWorkflowPin(
            "multiple distinct engine workflows or SHAs observed in a single run".to_owned(),
        ));
    }
    Ok(*distinct_shas.iter().next().expect("len == 1"))
}

/// Computes symmetric path differences (`--no-renames` equivalent) between two
/// `SourceTree` snapshots.
pub fn diff_trees_paths(
    tree_a: &dyn SourceTree,
    tree_b: &dyn SourceTree,
) -> Result<BTreeSet<RepoRelPath>, TreeError> {
    let mut all: BTreeSet<RepoRelPath> = BTreeSet::new();
    for p in tree_a.all_paths()? {
        all.insert(p);
    }
    for p in tree_b.all_paths()? {
        all.insert(p);
    }

    let mut changed = BTreeSet::new();
    for p in all {
        let ea = tree_a.entry(&p)?;
        let eb = tree_b.entry(&p)?;
        if ea != eb {
            changed.insert(p);
            continue;
        }
        if matches!(ea, Some(TreeEntry::Regular { .. }))
            && tree_a.read_blob(&p)? != tree_b.read_blob(&p)?
        {
            changed.insert(p);
        }
    }
    Ok(changed)
}

/// Evaluates `pull_request` TCB classification under
/// `⊔_{c ∈ {live_cfg, base_cfg, candidate_cfg}} EffectiveTcb(c, {T_b, T_e})`.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_pr_tcb(
    config_path: &RepoRelPath,
    live_cfg: &ChecksConfig,
    base_cfg: &ChecksConfig,
    candidate_cfg: &ChecksConfig,
    base_tree: &dyn SourceTree,
    event_tree: &dyn SourceTree,
    pr_number: u64,
    pr_head_sha: GitOid,
    reviews: &[PrReview],
) -> Result<TcbPlan, TcbError> {
    let trees: [&dyn SourceTree; 2] = [base_tree, event_tree];
    let maps = [
        compute_effective_tcb(live_cfg, config_path, &trees, event_tree)?,
        compute_effective_tcb(base_cfg, config_path, &trees, event_tree)?,
        compute_effective_tcb(candidate_cfg, config_path, &trees, event_tree)?,
    ];

    let changed = diff_trees_paths(base_tree, event_tree)?;
    let mut exec_changed = Vec::new();
    let mut pin_changed = Vec::new();
    for p in &changed {
        match classify_under_joined_tcb(&maps, p) {
            PathTrustClass::ExecutableTcb => exec_changed.push(p.clone()),
            PathTrustClass::DataPin => pin_changed.push(p.clone()),
            PathTrustClass::Untrusted => {}
        }
    }

    let tr = ControlPlaneTransition::new(base_cfg.control_plane(), candidate_cfg.control_plane());
    if tr.is_some() && exec_changed.is_empty() {
        exec_changed.push(config_path.clone());
    }

    let approved = is_owner_approved(
        reviews,
        &live_cfg.tcb.owner_user_ids,
        live_cfg.tcb.allow_owner_self_approval,
        &pr_head_sha,
    );

    if !exec_changed.is_empty() {
        if !approved {
            return Ok(TcbPlan::Blocked {
                paths: NonEmptyVec::new(exec_changed).expect("non-empty"),
            });
        }
        validate_workflows(event_tree, candidate_cfg)?;
        validate_codeowners(event_tree, candidate_cfg, config_path)?;
        return Ok(TcbPlan::RequiresOwnerApproval {
            required_prs: NonEmptyVec::singleton((pr_number, pr_head_sha)),
            control_plane_transition: tr,
        });
    }

    if !pin_changed.is_empty() {
        return Ok(TcbPlan::RequiresOwnerApproval {
            required_prs: NonEmptyVec::singleton((pr_number, pr_head_sha)),
            control_plane_transition: None,
        });
    }

    Ok(TcbPlan::NotRequired)
}

/// Commit-slice replay callback outcome for a single `MergeQueueEntry`:
/// returns the number of commits $n \ge 1$ consumed starting at `c_cur` if and
/// only if bare-Git replay matches `chain_trees[c_cur + 1 ..= c_cur + n]`.
pub trait CommitSliceReplayer {
    /// Attempts to replay `entry` onto commit index `c_cur`, returning `Ok(Some(n))`
    /// ($n \ge 1$) if `S_{c_cur+1}..S_{c_cur+n}` match tree-for-tree, or
    /// `Ok(None)` if this `(c_cur, entry)` alignment does not match.
    fn try_replay_entry(
        &self,
        c_cur: usize,
        entry: &MergeQueueEntry,
    ) -> Result<Option<usize>, String>;
}

/// Evaluates two-step `merge_group` attribution (`§4.3` Steps 3–5b) over a
/// first-parent commit chain $S_0 = B, S_1, \dots, S_k = E$ and landed chain
/// $M_0 = B, \dots, M_q = H_{\text{default}}$.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_merge_group_tcb(
    config_path: &RepoRelPath,
    live_cfg: &ChecksConfig,
    chain_trees: &[&dyn SourceTree],
    chain_tree_oids: &[GitOid],
    landed_tree_oids: &[GitOid],
    queue_entries: &[MergeQueueEntry],
    replayer: &dyn CommitSliceReplayer,
    reviews_by_pr: &dyn Fn(u64) -> Result<Vec<PrReview>, String>,
) -> Result<TcbPlan, TcbError> {
    if chain_trees.len() < 2 || chain_trees.len() != chain_tree_oids.len() {
        return Err(TcbError::MergeGroupRejected(
            "merge_group chain requires at least base S_0 and target S_k (k >= 1)".to_owned(),
        ));
    }
    let k = chain_trees.len() - 1;

    let parse_cfg_in = |t: &dyn SourceTree| -> Result<ChecksConfig, TcbError> {
        let bytes = t.read_blob(config_path)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|e| TcbError::MergeGroupRejected(format!("invalid checks.toml UTF-8: {e}")))?;
        ChecksConfig::parse_toml(text, config_path)
            .map_err(|e| TcbError::MergeGroupRejected(format!("checks.toml error: {e}")))
    };

    let mut parsed_opt_cfgs: Vec<Option<ChecksConfig>> = Vec::with_capacity(chain_trees.len());
    let mut seen_cfg = false;
    for (idx, t) in chain_trees.iter().enumerate() {
        ensure_no_symlink_at_or_ancestors(*t, config_path, true)?;
        if t.kind_of(config_path)?.is_some() {
            seen_cfg = true;
            parsed_opt_cfgs.push(Some(parse_cfg_in(*t)?));
        } else {
            if seen_cfg {
                return Err(TcbError::MergeGroupRejected(format!(
                    "`{config_path}` deleted at merge_group step S_{idx}"
                )));
            }
            parsed_opt_cfgs.push(None);
        }
    }
    let first_present_cfg = parsed_opt_cfgs
        .iter()
        .find_map(Option::as_ref)
        .ok_or_else(|| {
            TcbError::MergeGroupRejected(format!("merge_group target S_{k} lacks `{config_path}`"))
        })?
        .clone();
    let chain_cfgs: Vec<ChecksConfig> = parsed_opt_cfgs
        .into_iter()
        .map(|opt| opt.unwrap_or_else(|| first_present_cfg.clone()))
        .collect();

    // Step 3: Revert-Proof Global Stepwise Fast Path across `S_0..S_k`.
    let mut fast_maps = Vec::with_capacity(chain_cfgs.len() + 1);
    fast_maps.push(compute_effective_tcb(
        live_cfg,
        config_path,
        chain_trees,
        chain_trees[k],
    )?);
    for c in &chain_cfgs {
        fast_maps.push(compute_effective_tcb(
            c,
            config_path,
            chain_trees,
            chain_trees[k],
        )?);
    }
    let mut any_step_touched_tcb_or_pin = false;
    for r in 1..=k {
        let step_diff = diff_trees_paths(chain_trees[r - 1], chain_trees[r])?;
        if step_diff
            .iter()
            .any(|p| classify_under_joined_tcb(&fast_maps, p) != PathTrustClass::Untrusted)
        {
            any_step_touched_tcb_or_pin = true;
            break;
        }
    }
    if !any_step_touched_tcb_or_pin
        && chain_cfgs[0].control_plane() == chain_cfgs[k].control_plane()
    {
        return Ok(TcbPlan::NotRequired);
    }

    // Step 4: Contiguous Landed-Prefix Verification (`M_0..M_q` vs `S_0..S_k`).
    if landed_tree_oids.is_empty() || landed_tree_oids[0] != chain_tree_oids[0] {
        return Err(TcbError::MergeGroupRejected(
            "landed prefix base tree M_0 != S_0".to_owned(),
        ));
    }
    let q = landed_tree_oids.len() - 1;
    if q > k {
        return Err(TcbError::MergeGroupRejected(format!(
            "default_branch advanced {q} commits past base (> queue depth {k})"
        )));
    }
    for i in 1..=q {
        if landed_tree_oids[i] != chain_tree_oids[i] {
            return Err(TcbError::MergeGroupRejected(format!(
                "landed commit M_{i} tree diverged from merge_group S_{i} (concurrent revert/divergence)"
            )));
        }
    }
    let p = q;
    if p == k {
        return Ok(TcbPlan::NotRequired);
    }

    // Step 5a: Offset-aware `(c_start, e_start)` alignment + replay to `c_cur == k`.
    let leading_locked_count = queue_entries
        .iter()
        .take_while(|e| e.state == MergeQueueEntryState::Locked)
        .count();

    type MatchedSlice = (MergeQueueEntry, usize, usize);
    let mut valid_alignments: Vec<Vec<MatchedSlice>> = Vec::new();

    for e_start in 0..=leading_locked_count.min(queue_entries.len()) {
        for c_start in 0..=p {
            // Verify `entries[0..e_start]` replays `S_{c_start}..S_p` ending at `p`.
            let mut c_cur = c_start;
            let mut prefix_ok = true;
            for entry in &queue_entries[0..e_start] {
                if c_cur >= p {
                    prefix_ok = false;
                    break;
                }
                match replayer
                    .try_replay_entry(c_cur, entry)
                    .map_err(TcbError::MergeGroupRejected)?
                {
                    Some(n) if n >= 1 && c_cur + n <= p => {
                        c_cur += n;
                    }
                    _ => {
                        prefix_ok = false;
                        break;
                    }
                }
            }
            if !prefix_ok || c_cur != p {
                continue;
            }

            // Now replay `entries[e_start..]` from `c_cur = p` until `c_cur == k`.
            let mut slices: Vec<MatchedSlice> = Vec::new();
            let mut suffix_ok = true;
            for entry in &queue_entries[e_start..] {
                if c_cur == k {
                    break;
                }
                match replayer
                    .try_replay_entry(c_cur, entry)
                    .map_err(TcbError::MergeGroupRejected)?
                {
                    Some(n) if n >= 1 && c_cur + n <= k => {
                        slices.push((entry.clone(), c_cur, c_cur + n));
                        c_cur += n;
                    }
                    _ => {
                        suffix_ok = false;
                        break;
                    }
                }
            }
            if suffix_ok && c_cur == k {
                valid_alignments.push(slices);
            }
        }
    }

    if valid_alignments.len() != 1 {
        return Err(TcbError::MergeGroupRejected(format!(
            "expected unique mergeQueue prefix alignment to S_{k}, matched {}",
            valid_alignments.len()
        )));
    }
    let matched_slices = valid_alignments.into_iter().next().expect("len == 1");

    // Step 5b: Stepwise intra- and inter-PR classification across `T_all = S_p..S_k`
    // and `C_all = { live_cfg } ∪ { cfg(T) | T ∈ T_all }`.
    let t_all = &chain_trees[p..=k];
    let c_all = &chain_cfgs[p..=k];
    validate_workflows(chain_trees[k], &chain_cfgs[k])?;
    validate_codeowners(chain_trees[k], &chain_cfgs[k], config_path)?;

    let mut step_maps = Vec::with_capacity(c_all.len() + 1);
    step_maps.push(compute_effective_tcb(
        live_cfg,
        config_path,
        t_all,
        chain_trees[k],
    )?);
    for c in c_all {
        step_maps.push(compute_effective_tcb(
            c,
            config_path,
            t_all,
            chain_trees[k],
        )?);
    }

    let tr =
        ControlPlaneTransition::new(chain_cfgs[p].control_plane(), chain_cfgs[k].control_plane());

    let mut required_prs: Vec<(u64, GitOid)> = Vec::new();
    for (entry, s_a, s_b) in &matched_slices {
        let mut pr_touches_exec = false;
        let mut pr_touches_pin = false;
        for t_idx in (*s_a + 1)..=*s_b {
            let step_diff = diff_trees_paths(chain_trees[t_idx - 1], chain_trees[t_idx])?;
            for path in &step_diff {
                match classify_under_joined_tcb(&step_maps, path) {
                    PathTrustClass::ExecutableTcb => pr_touches_exec = true,
                    PathTrustClass::DataPin => pr_touches_pin = true,
                    PathTrustClass::Untrusted => {}
                }
            }
            if chain_cfgs[t_idx - 1].control_plane() != chain_cfgs[t_idx].control_plane() {
                pr_touches_exec = true;
            }
        }
        if !pr_touches_exec && pr_touches_pin {
            for pid in chain_cfgs[*s_b].pins.keys() {
                if chain_cfgs[*s_b]
                    .evaluate_pin(chain_trees[*s_b], pid)
                    .is_err()
                {
                    pr_touches_exec = true;
                }
            }
        }
        if pr_touches_exec || pr_touches_pin {
            let reviews = reviews_by_pr(entry.pr_number).map_err(TcbError::MergeGroupRejected)?;
            if !is_owner_approved(
                &reviews,
                &live_cfg.tcb.owner_user_ids,
                live_cfg.tcb.allow_owner_self_approval,
                &entry.head_oid,
            ) {
                return Err(TcbError::MergeGroupRejected(format!(
                    "queued PR #{} (`{}`) touches TCB/DataPin without live owner approval",
                    entry.pr_number, entry.head_oid
                )));
            }
            required_prs.push((entry.pr_number, entry.head_oid));
        }
    }

    if let Some(tr_val) = tr {
        if required_prs.is_empty() {
            return Err(TcbError::MergeGroupRejected(
                "control-plane transition occurred without an attributed approved PR".to_owned(),
            ));
        }
        Ok(TcbPlan::RequiresOwnerApproval {
            required_prs: NonEmptyVec::new(required_prs).expect("non-empty"),
            control_plane_transition: Some(tr_val),
        })
    } else if let Ok(non_empty) = NonEmptyVec::new(required_prs) {
        Ok(TcbPlan::RequiresOwnerApproval {
            required_prs: non_empty,
            control_plane_transition: None,
        })
    } else {
        Ok(TcbPlan::NotRequired)
    }
}

/// Checks contiguous landed-prefix condition (`q <= k ∧ ∀ i ∈ 1..=q: M_i == S_i`)
/// against `plan.merge_group_chain_trees` (`(B, [tree(S_1), ..., tree(S_k)])`).
pub fn verify_landed_prefix(
    expected_base: &GitOid,
    plan_chain_trees: &[GitOid],
    landed_base: &GitOid,
    landed_chain_trees: &[GitOid],
) -> bool {
    if expected_base != landed_base {
        return false;
    }
    let k = plan_chain_trees.len();
    let q = landed_chain_trees.len();
    if q > k {
        return false;
    }
    plan_chain_trees[..q] == landed_chain_trees[..]
}
