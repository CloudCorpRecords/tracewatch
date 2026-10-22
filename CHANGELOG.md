# Changelog

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
