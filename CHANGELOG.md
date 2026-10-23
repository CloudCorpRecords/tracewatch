# Changelog

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
