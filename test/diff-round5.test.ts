/**
 * Round 5 diff tests: one diff scenario per new tool (mcpvet,
 * depguard, flowcheck). Each imports two scans whose finding sets
 * differ in a known way and asserts the NEW, RESOLVED, and CHANGED
 * buckets, plus verdict moves and, for depguard, that the scan record
 * carries the diff context the findings were produced against.
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

const ROOT = "/repos/demo";
let dir: string;
let store: Store;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "tracewatch-r5-"));
  store = new Store(join(dir, "store"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const mcpvetReport = (findings: Record<string, unknown>[], verdict: string) => ({
  tool: "mcpvet",
  version: "0.1.1",
  target: ROOT,
  kind: "server",
  name: "demo-server",
  verdict,
  counts: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0, total: findings.length },
  findings,
  notes: [],
});

const harvest = {
  rule: "CONFIG-ENV-HARVEST",
  severity: "high",
  file: "claude_desktop_config.json",
  line: 3,
  evidence: "env block with 8 keys, 4 credential-shaped",
  detail: "wide env block",
};
const unpinned = {
  rule: "CONFIG-UNPINNED-NPX",
  severity: "high",
  file: "claude_desktop_config.json",
  line: 3,
  evidence: "npx -y demo-server",
  detail: "unpinned npx autostart",
};

describe("round 5 diffs", () => {
  it("mcpvet: a removed finding resolves, an added finding is new, verdict move recorded", () => {
    importReports(store, { repo: "demo", path: ROOT, at: "2026-01-01T00:00:00.000Z", reports: [{ tool: "mcpvet", report: mcpvetReport([harvest], "REVIEW") }] });
    importReports(store, { repo: "demo", path: ROOT, at: "2026-01-02T00:00:00.000Z", reports: [{ tool: "mcpvet", report: mcpvetReport([unpinned], "REVIEW") }] });
    const diff = diffScans(store, "demo");
    assert.equal(diff.added.length, 1);
    assert.equal(diff.added[0].rule, "CONFIG-UNPINNED-NPX");
    assert.equal(diff.resolved.length, 1);
    assert.equal(diff.resolved[0].rule, "CONFIG-ENV-HARVEST");
    assert.equal(diff.changed.length, 0);
    // Third identical scan diffs empty.
    importReports(store, { repo: "demo", path: ROOT, at: "2026-01-03T00:00:00.000Z", reports: [{ tool: "mcpvet", report: mcpvetReport([unpinned], "REVIEW") }] });
    const empty = diffScans(store, "demo");
    assert.equal(empty.added.length + empty.resolved.length + empty.changed.length, 0);
    assert.equal(empty.unchangedCount, 1);
  });

  it("mcpvet: an evidence edit is a changed finding, not new plus resolved", () => {
    importReports(store, { repo: "demo", path: ROOT, at: "2026-01-01T00:00:00.000Z", reports: [{ tool: "mcpvet", report: mcpvetReport([harvest], "REVIEW") }] });
    const edited = { ...harvest, evidence: "env block with 9 keys, 5 credential-shaped" };
    importReports(store, { repo: "demo", path: ROOT, at: "2026-01-02T00:00:00.000Z", reports: [{ tool: "mcpvet", report: mcpvetReport([edited], "REVIEW") }] });
    const diff = diffScans(store, "demo");
    assert.equal(diff.changed.length, 1);
    assert.ok(diff.changed[0].changes.some((c) => c.includes("evidence changed")));
  });

  it("flowcheck: severity regrade is changed, a fixed workflow resolves, verdict move recorded", () => {
    const fc = (findings: Record<string, unknown>[], verdict: string) => ({
      tool: "flowcheck",
      version: "0.1.0",
      target: ROOT,
      verdict,
      counts: { files: 1, jobs: 1, findings: findings.length, bySeverity: {} },
      findings,
      plans: [],
    });
    const writeAll = { rule: "FC-PERMS-WRITE-ALL", severity: "critical", file: "ci.yml", line: 4, message: "write-all grants every scope" };
    const timeout = { rule: "FC-NO-TIMEOUT", severity: "low", file: "ci.yml", job: "test", line: 9, message: "no timeout-minutes" };
    importReports(store, { repo: "demo", path: ROOT, at: "2026-01-01T00:00:00.000Z", reports: [{ tool: "flowcheck", report: fc([writeAll, timeout], "EXPOSED") }] });
    const regraded = { ...writeAll, severity: "high" };
    importReports(store, { repo: "demo", path: ROOT, at: "2026-01-02T00:00:00.000Z", reports: [{ tool: "flowcheck", report: fc([regraded], "REVIEW") }] });
    const diff = diffScans(store, "demo");
    assert.equal(diff.resolved.length, 1);
    assert.equal(diff.resolved[0].rule, "FC-NO-TIMEOUT");
    assert.equal(diff.changed.length, 1);
    assert.ok(diff.changed[0].changes.some((c) => c.includes("severity: critical -> high")));
    const move = diff.verdictMoves.find((m) => m.tool === "flowcheck");
    assert.deepEqual([move?.from, move?.to], ["EXPOSED", "REVIEW"]);
    const health = repoHealth(store, "demo");
    assert.equal(health.open.byTool.flowcheck, 1);
  });

  it("depguard: version move is changed with version detail, context rides the scan record", () => {
    const dg = (versionTo: string, withTypo: boolean) => ({
      tool: "depguard",
      version: "0.1.0",
      path: `${ROOT}/current`,
      base: "HEAD~1",
      mode: "offline",
      verdict: withTypo ? "HIGH-RISK" : "REVIEW",
      counts: { added: 1, removed: 0, changed: 0, findings: withTypo ? 1 : 0, high: withTypo ? 1 : 0, medium: 0, low: 0 },
      changes: [
        {
          name: "lodahs",
          change: "added",
          rangeTo: `^${versionTo}`,
          versionTo,
          verdict: withTypo ? "HIGH-RISK" : "REVIEW",
          findings: withTypo
            ? [{ rule: "TYPOSQUAT-SUSPECT", severity: "high", source: "local", evidence: "edit distance 1 from lodash" }]
            : [{ rule: "NEW-DEPENDENCY", severity: "medium", source: "local", evidence: "new dependency lodahs" }],
        },
      ],
      repoFindings: [],
      caps: {},
      warnings: [],
    });
    importReports(store, { repo: "demo", path: ROOT, at: "2026-01-01T00:00:00.000Z", reports: [{ tool: "depguard", report: dg("1.0.0", true) }] });
    importReports(store, { repo: "demo", path: ROOT, at: "2026-01-02T00:00:00.000Z", reports: [{ tool: "depguard", report: dg("1.0.1", true) }] });
    const diff = diffScans(store, "demo");
    assert.equal(diff.changed.length, 1);
    assert.ok(diff.changed[0].changes.some((c) => c.includes("version:")), JSON.stringify(diff.changed[0].changes));
    // Scan record carries the diff context.
    const scans = store.scans("demo");
    assert.equal(scans[0].tools.depguard?.context?.base, "HEAD~1");
    assert.equal(scans[0].tools.depguard?.context?.baseKind, "ref");
    assert.equal(scans[0].tools.depguard?.context?.head, `${ROOT}/current`);
    // A scan where the typosquat rule is replaced reads as resolved plus new.
    importReports(store, { repo: "demo", path: ROOT, at: "2026-01-03T00:00:00.000Z", reports: [{ tool: "depguard", report: dg("1.0.1", false) }] });
    const diff2 = diffScans(store, "demo");
    assert.equal(diff2.resolved.length, 1);
    assert.equal(diff2.resolved[0].rule, "TYPOSQUAT-SUSPECT");
    assert.equal(diff2.added.length, 1);
    assert.equal(diff2.added[0].rule, "NEW-DEPENDENCY");
  });
});
