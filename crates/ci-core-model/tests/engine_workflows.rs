//! Structure tests for the reusable engine workflows in `.github/workflows/`.
//!
//! The gate's verdict depends on which jobs and steps these workflows run
//! after a check fails, and none of that is exercised by `cargo test`
//! otherwise. These tests pin the conditions the gate relies on.

use std::path::PathBuf;

use serde_yaml_ng::Value;

fn load_workflow(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_yaml_ng::from_str(&text).unwrap_or_else(|e| panic!("parsing {name}: {e}"))
}

fn job<'a>(wf: &'a Value, id: &str) -> &'a Value {
    wf.get("jobs")
        .and_then(|j| j.get(id))
        .unwrap_or_else(|| panic!("missing job `{id}`"))
}

fn step_if<'a>(job: &'a Value, step_name: &str) -> Option<&'a str> {
    let step = job
        .get("steps")
        .and_then(Value::as_sequence)
        .expect("job has steps")
        .iter()
        .find(|s| s.get("name").and_then(Value::as_str) == Some(step_name))
        .unwrap_or_else(|| panic!("missing step `{step_name}`"));
    step.get("if").and_then(Value::as_str)
}

fn normalized(cond: &str) -> String {
    cond.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Shard metadata must be uploaded whenever the execute step ran, including
/// when a check failed, so the gate gets one record per planned shard.
#[test]
fn shard_metadata_is_uploaded_after_failed_checks() {
    for name in ["ci.yml", "ci-pr.yml"] {
        let wf = load_workflow(name);
        let execute = job(&wf, "execute");
        let cond = step_if(execute, "Upload shard metadata artifact")
            .unwrap_or_else(|| panic!("{name}: shard metadata upload has no `if:`"));
        assert_eq!(
            normalized(cond),
            "${{ !cancelled() && steps.exec.outcome != 'skipped' }}",
            "{name}: shard metadata upload condition"
        );
    }
}

/// Output and cache blobs must stay gated on `has_shard_blob`, which
/// `ci-core execute` sets only when every check in the shard passed.
#[test]
fn shard_blobs_are_uploaded_only_for_passing_shards() {
    let wf = load_workflow("ci.yml");
    let execute = job(&wf, "execute");
    assert_eq!(
        step_if(execute, "Upload shard output and cache staging blobs").map(normalized),
        Some("steps.exec.outputs.has_shard_blob == 'true'".to_owned())
    );
}

/// `publish` must run whenever the plan has pending work, regardless of how
/// `build-images` or `execute` ended: the gate rejects a skipped `publish`
/// when `needs_publish` is set, and `ci-core publish` re-evaluates the gate
/// before any side effect.
#[test]
fn publish_runs_after_failed_execute() {
    let wf = load_workflow("ci.yml");
    let cond = job(&wf, "publish")
        .get("if")
        .and_then(Value::as_str)
        .expect("publish has `if:`");
    assert_eq!(
        normalized(cond),
        "!cancelled() && needs.plan.outputs.needs_publish == 'true' && \
         needs.plan.result == 'success'"
    );
}
