# Self-Service Repository Ruleset Configuration (`examples/zerocopy/`)

`ci-core` deploys using repository-level settings (`Settings -> Rules -> Rulesets`)
and tracked repository files only, requiring zero organization-level settings and
zero hosted GitHub App or webhook infrastructure.

## 1. Organization Repository + Merge Queue (`ghec` / `fpt`, e.g. `google/zerocopy`)

Configure **two** companion Repository Branch Rulesets so branch-creation
restrictions cover feature branches (`Obligation O8`) while PR, status-check,
and merge-queue gates apply to `~DEFAULT_BRANCH`:

### Ruleset A — Upstream Branch Integrity (`Target: ~ALL`)
- **Enforcement status:** Active
- **Bypass list:** Only `@google/zerocopy-maintainers` (or repository admins as
  needed for release branches; zero general `write` contributor bypass so
  non-owners open fork PRs with read-only `GITHUB_TOKEN`)
- **Rules enabled:**
  - `Restrict creations`
  - `Restrict updates` (for non-bypassed actors; Merge Queue updates `main`)
  - `Restrict deletions`
  - `Block force pushes`

### Ruleset B — Default-Branch Gate & Merge Queue (`Target: ~DEFAULT_BRANCH`)
- **Enforcement status:** Active
- **Bypass list:** Empty (`0` bypass actors so `<gate_check_name>` is mandatory)
- **Rules enabled:**
  - `Require a pull request before merging`:
    - `Require review from Code Owners = true`
    - `Dismiss stale pull request approvals when new commits are pushed = true`
  - `Require status checks to pass`:
    - During shadow bring-up (`shadow_mode: true`): keep existing required checks;
      leave `ci-core / gate` non-blocking until Bring-Up Probes #1-#2 pass.
    - At enforcement cutover (`shadow_mode: false`, renaming caller to
      `.github/workflows/ci.yml` with `gate_check_name = "ci / gate"`): require
      `ci / gate` pinned to **GitHub Actions** (`app_id = 15368`).
  - `Require merge queue` (configured with the repository's chosen `MERGE`,
    `SQUASH`, or `REBASE` method).

### GHCR Package Visibility
- After the first `main` or `merge_group` run creates the two GHCR packages:
  - Set `ghcr.io/<owner>/<repo>/ci-cas` visibility to **Public** so fork PRs and
    unauthenticated `ci-core run-local` runs receive verified receipt/image hits.
  - Keep `ghcr.io/<owner>/<repo>/ci-cache` **Private** and Actions-linked to the
    consumer repository only.

---

## 2. Solo-Owner Personal Repository (`fpt`, No Merge Queue)

On personal user-owned repositories where Merge Queue is unavailable and GitHub
rejects self-`APPROVED` PR reviews with `HTTP 422`:
1. Set `allow_owner_self_approval = true` and `codeowners = ["@<username>"]` in
   `ci/checks.toml` (approving TCB/pin PRs via PR review comment
   `/ci-core approve <40-hex-pr-head-sha>` and revoking via `/ci-core unapprove`).
2. Split `~DEFAULT_BRANCH` protection into **two** Repository Rulesets:
   - **Ruleset 1 (`0` bypass actors):** `Restrict creations/updates/deletions`,
     `Block force pushes`, `Require a pull request before merging` (`0` approval
     count), and `Require status checks to pass` (`ci / gate`, `app_id = 15368`,
     `Require branches to be up to date before merging = true`).
   - **Ruleset 2 (`RepositoryAdmin` `"Pull request"` bypass):** `Require a pull
     request before merging` with `Require review from Code Owners = true` and
     `Dismiss stale pull request approvals = true` (protecting against any
     collaborators while allowing the solo owner to merge once `ci / gate` is
     green).

---

## 3. Fork-PR Token Ceiling Contingency (Bring-Up Probe #1)

If GitHub Actions statically rejects a fork `pull_request` run when the caller
workflow declares `id-token: write` in its top-level `permissions` ceiling even
though `publish` is skipped on `pull_request`, split the caller into two files
with zero `ci-core` binary changes:
- `.github/workflows/ci.yml`: `on: pull_request`, read-only ceiling
  `{ actions: read, contents: read, packages: read, pull-requests: read }`, job
  `ci` (`name: ci`).
- `.github/workflows/ci-trusted.yml`: `on: { merge_group: {}, push: { branches: [main] } }`,
  ceiling `{ actions: read, contents: read, packages: write, id-token: write, pull-requests: read }`,
  job `ci` (`name: ci`).
- Update `caller_workflows = [".github/workflows/ci.yml", ".github/workflows/ci-trusted.yml"]`
  and `gate_check_name = "ci / gate"` in `ci/checks.toml`.
