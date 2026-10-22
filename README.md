# tracewatch

Observability, tracking, and root-cause for the Security Wave.

The tranche 1 tools (hookcheck, actionpin, injectcheck) answer "what is wrong right now, in this one scan." tracewatch is the wave's memory and stopwatch. It ingests their JSON reports over time and answers the questions an incident actually turns on:

- What changed since the last scan? Did a pin silently regress to a mutable tag? Did the ref under an already-pinned action move? That move is the tj-actions shape from March 2025: a tag retargeted under every repo that trusted it, invisible to anyone who only ever ran one scan.
- Where did this finding come from? tracewatch blames a finding to the commit that introduced it (git pickaxe on the finding's own content) and to the pull request that carried it, and labels every statement confirmed, inferred, or not established.
- How fast do we notice? Watch mode scans new issues, PRs, files, and tree changes on arrival and records time-to-detect for each one, so "early detection" is a measured number. The comparison point matters: hosted AI firewalls detect at prompt time, after the agent has already read the content. tracewatch detects at rest and on arrival, before any agent session exists.
- Is the estate getting better? Verdict trends, open findings by tool and severity, mean time open for resolved findings, and detection latency stats, per repo, over the whole scan history.

Deterministic, offline-first, local store you can grep. No hosted backend, no account, no telemetry.

## Install

```
npx -y @reneturcios/tracewatch --version
npm install -g @reneturcios/tracewatch
docker run -i --rm ghcr.io/cloudcorprecords/tracewatch mcp
```

## Quick start

```
# scan a repo with all three tools and start tracking it
tracewatch ingest ~/src/myrepo

# what changed since the previous scan?
tracewatch diff myrepo

# where did this finding come from?
tracewatch blame myrepo --finding tw_0123456789abcdef

# health over time
tracewatch report myrepo

# watch a directory and scan new content on arrival
tracewatch watch ~/src/myrepo --interval 30
```

## What it tracks

Every ingest stores one scan record (timestamp, tool versions, verdicts, git HEAD) plus one observation per finding. Findings carry stable IDs: a hash of tool, rule, normalized location, and a content signature. The same finding keeps its identity across scans and tool versions; a content edit keeps the identity and changes the ID version, which is what diff reports as CHANGED.

Diff groups: NEW, RESOLVED, CHANGED (with field-level old to new), verdict moves, and REF EVENTS. A ref event fires whenever an action's ref or classification moves, with both values spelled out:

- pin-regression: PINNED to MUTABLE or BRANCH
- pin-improvement: MUTABLE or BRANCH to PINNED
- ref-move: the ref changed inside one classification (for a pinned action, the SHA itself moved)

## Blame (root cause)

```
tracewatch blame myrepo --rule CURL-PIPE-SH --file package.json
tracewatch blame myrepo --finding tw_0123456789abcdef --json
```

Evidence is labeled, never blended:

- CONFIRMED: the introducing commit from `git log -S` on the finding's needle in your local clone; the current-line commit from `git blame`; the PR association from the GitHub API (`commits/{sha}/pulls`) when the clone has a GitHub remote; ref history and first/last seen from the store itself.
- INFERRED: circumstantial statements, written as inferences (for example, when the introducing commit and the current-line commit differ, the line was rewritten later without introducing the content).
- NOT ESTABLISHED: whatever could not be proven, with the reason (no clone recorded, no GitHub remote, API unreachable). Provenance is never guessed to fill the page.

## Watch and time-to-detect

```
tracewatch watch ~/src/myrepo --interval 60 --alerts alerts.jsonl
tracewatch watch owner/repo --path ~/src/myrepo-clone --interval 60
```

Local mode polls a directory: new or changed text files are scanned with injectcheck the poll they appear in; a git HEAD move triggers a full ingest plus diff. GitHub mode polls an owner/repo slug: new issues and PRs are scanned on arrival, HEAD moves are recorded (and scanned when you pass a local clone with --path). Every detection writes a record with time-to-detect = detection time minus the content's own creation time (issue created_at, commit time, file birth time). State checkpoints after every cycle, so a restarted watch resumes without re-alerting history. Alerts stream as JSONL to stdout and to the --alerts file.

Polling is the portable fallback. The fastest path is event-driven, in CI:

```yaml
name: tracewatch-issues
on:
  issues:
    types: [opened, edited]
  pull_request:
    types: [opened, edited, synchronize]
permissions:
  contents: read
jobs:
  scan-new-content:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4
        with:
          node-version: 24
      - name: Scan the new issue or PR body on arrival
        env:
          BODY: ${{ github.event.issue.body || github.event.pull_request.body }}
        run: |
          printf '%s' "$BODY" > /tmp/body.md
          npx -y @reneturcios/injectcheck file /tmp/body.md --json > /tmp/report.json
          npx -y @reneturcios/tracewatch import ${{ github.repository }} --report injectcheck=/tmp/report.json
```

Known limit, stated plainly: GitHub watch mode reads through the local ghapi helper, whose output truncates long responses; an issue poll that cannot be parsed in full is logged as a watch note and retried next cycle rather than partially trusted. The CI pattern above has no such limit and is the recommended production path for issue scanning.

## Reports

```
tracewatch report myrepo          # human
tracewatch report myrepo --json   # machine
tracewatch findings myrepo --tool hookcheck --status open
```

The health report carries the verdict trend across every scan, open findings by tool and severity, resolved count, mean time open for resolved findings (first-seen scan to the scan where the finding disappeared), all ref events, and detection latency stats (count, median, max, by kind).

## MCP

`tracewatch mcp` serves a stdio MCP server with seven tools:

| Tool | What it does |
| --- | --- |
| ingest_scan | Run the three tools on a local path and store the scan |
| diff_scans | NEW / RESOLVED / CHANGED, verdict moves, ref events between two scans |
| finding_provenance | Introducing commit, current-line commit, PR, ref history for one finding |
| repo_health | Verdict trend, open findings, mean time open, detection latency |
| watch_status | Every tracked repo: scans, last scan, open findings, median TTD |
| list_findings | Tracked findings filtered by tool, severity, status |
| explain_finding | The full evidence bundle for one finding, written to act on |

## Store

Append-only JSONL under ~/.tracewatch (override with --store <dir> or TRACEWATCH_STORE): scans.jsonl, findings.jsonl, detections.jsonl, alerts.jsonl, plus watch-state.json checkpoints. Plain text on purpose. Finding status is derived from the observation series on every read, never stored as mutable state, so the store cannot disagree with itself. Identical store state always renders identical diff and report output.

Exit codes: 0 success or no changes, 1 a diff found changes, 2 usage error or total failure, 141 the reader closed the output pipe before the report was delivered.

## Honesty rules

- A verdict is a scan result, never a safety claim. tracewatch reports what the three tools found and when; it does not certify a repo clean.
- Time-to-detect is measured against the content's own timestamps and recorded per detection; the report shows the distribution, not a best case.
- Blame separates confirmed evidence from inference and says "not established" out loud.

MIT. Part of the Security Wave: hookcheck (persistence hooks), actionpin (Actions pinning), injectcheck (prompt injection in agent-read content), tracewatch (observability and root cause).
