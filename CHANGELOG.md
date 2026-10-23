# Changelog

## 0.2.1 (2026-10-23)

Production-validation fix (stream 4, problem S4-4), applied on top
of 0.2.0: finding identity no longer includes the absolute checkout
path for imported reports.

- Adapters now normalize finding file paths against the scan root
  the report records about itself (actionpin/hookcheck `path`,
  injectcheck `target`) when the caller supplies no root, and
  `normalizePath` falls back to the repo-relative suffix at the
  `.github/` anchor when no root covers an absolute path. Before
  this, `tracewatch import` without `--path` left actionpin's
  absolute workflow paths in finding identity, so the same repo
  scanned from a different absolute path (every CI runner) churned
  all actionpin findings as added + resolved, and a real
  setup-python v5 -> v6 ref bump produced no refEvent.
- With identities aligned, a ref bump on an otherwise unchanged
  action now diffs as one CHANGED finding carrying a `ref-move`
  RefEvent with both values (the diff logic already supported it;
  it simply never saw matching identities from imports).
- Regression tests in test/sw4-paths.test.ts: two snapshots of the
  same repo recorded at different absolute roots import to a diff
  with zero added / resolved / changed, and the v5 -> v6 bump
  yields exactly one changed finding and one refEvent.
- Process note: an earlier commit labeled 0.1.2 was pushed onto
  0.2.0 during a concurrent-release race from a stale 0.1.1
  checkout and reverted the 0.2.0 adapter work in the tree (the
  build caught it). That commit was never published to any
  surface; this release restores the 0.2.0 content and applies
  the SW-4 change on top of it.

## 0.2.0 (2026-10-23)

- Adapters for the tranche 2 tools: tracewatch now ingests mcpvet 0.1.1, depguard 0.1.0, and flowcheck 0.1.0 reports alongside hookcheck, actionpin, and injectcheck, in both direct-run ingest and report import. Findings from all six tools flow through diff, list_findings, explain_finding, blame, and repo_health with no special cases.
- mcpvet: findings normalize from rule, severity (the shared factory scale, critical through info), file, line, evidence, and detail; the evidence is the blame needle and the content signature input.
- flowcheck: findings normalize from rule, severity, file, line, job, and message; the job joins the finding location so the same rule in two jobs of one workflow versions as two findings.
- depguard: the structural exception. Its reports have no top-level findings array; findings hang off dependency changes plus a repo-level list. The adapter flattens both, keys each finding to its dependency in the manifest, and preserves the diff context (base ref or path or none, head path, run mode, per-finding change kind and version move) on every finding and on the scan record, so a later diff says what changed against what. A clean dependency change with no findings produces no observation. Blame pickaxes the dependency name in package.json.
- Direct-run boundary, stated plainly: depguard runs in offline snapshot mode on a bare target (base none); full base/head scans arrive by importing a report produced with --base or --base-path. The README carries the same note.
- CLI and MCP tool filters now validate tool names against the six known tools instead of silently mistyping an unknown one.
- Tests: 35 passing (12 new: adapter shape, severity, malformed-entry tolerance, and depguard diff-context tests per new tool, plus one diff scenario per new tool).

## 0.1.1 (2026-10-22)

- Blame fix: the introducing-commit pickaxe now falls back, when the finding's full content string finds no commit, to the finding's own lines (longest first), each proven by the same `git log -S` scoped to the finding's file. In 0.1.0 a hookcheck finding on a workflow run step could never be attributed: hookcheck reports the step command dedented, while the committed workflow file indents every line, so the multi-line needle occurred nowhere in the file's history and blame reported the introducing commit as NOT ESTABLISHED even for the commit that added the file. Single-line findings (for example a package.json install hook) are unchanged, and a finding whose lines no commit introduced still reports NOT ESTABLISHED with its reason. Regression tests cover the workflow shape and the honest-miss shape.

## 0.1.0 (2026-10-22)

First release. tracewatch is the Security Wave's observability, tracking, and root-cause layer over hookcheck, actionpin, and injectcheck.

- Ingest: run the three published tools against a local path (or import their JSON report files) and store timestamped scan records plus per-finding observations in an append-only JSONL store.
- Stable finding IDs from tool, rule, normalized location, and content signature; identity survives content edits so diffs read as CHANGED, not as new plus resolved noise.
- Diff: NEW, RESOLVED, CHANGED with field-level moves, verdict moves, and first-class action ref events (pin-regression, pin-improvement, ref-move) with both values.
- Blame: introducing commit via git pickaxe, current-line commit via git blame, PR association via the GitHub API, ref history from the store; confirmed, inferred, and not-established evidence kept separate.
- Watch: local directory and GitHub slug polling; new text files, issues, and PRs scanned on arrival; tree changes re-scanned and diffed; time-to-detect recorded per detection; checkpointed state resumes without re-alerting.
- Health reports: verdict trend, open findings by tool and severity, mean time open for resolved findings, ref events, detection latency stats.
- MCP server (stdio) with ingest_scan, diff_scans, finding_provenance, repo_health, watch_status, list_findings, explain_finding.
- Factory emit contract from day one: flush-aware report output, exit 141 on a closed pipe, spawned-CLI pipe regression tests.
