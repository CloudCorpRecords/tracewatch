/**
 * SW-4 (production validation stream 4, problem S4-4): the same repo
 * scanned from two different absolute paths churned every actionpin
 * finding in the diff (added + resolved, zero changed), and a real
 * setup-python v5 -> v6 ref bump produced no refEvent. Root cause:
 * actionpin reports embed the ABSOLUTE workflow path and record the
 * scan root in the report's own `path` field, but import only
 * normalized against the caller's --path (empty when not given), so
 * finding identity (tool|file|action|rule) differed per checkout
 * directory. CI checkouts differ per runner and run, so production
 * diffs showed total actionpin churn and no trend signal.
 *
 * The fix normalizes at adapt/import time: strip the scan root the
 * REPORT records (path for actionpin/hookcheck, target for
 * injectcheck), with a repo-relative suffix fallback (the
 * .github/workflows anchor) when no root is recorded anywhere.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/store.js";
import { importReports } from "../src/ingest.js";
import { diffScans } from "../src/diff.js";
import { adaptActionpin } from "../src/adapters.js";

const ROOT_A = "/tmp/runner-a/work/httpx";
const ROOT_B = "/home/ci/checkouts/httpx";

function pinReport(root: string, pythonRef: string) {
  return {
    path: root,
    verdict: "PARTIAL",
    actions: [
      {
        workflow: `${root}/.github/workflows/test.yml`,
        line: 18,
        uses: "actions/checkout@v4",
        action: "actions/checkout",
        ref: "v4",
        classification: "MUTABLE",
        ownerType: "official",
        rawLine: "      - uses: actions/checkout@v4",
      },
      {
        workflow: `${root}/.github/workflows/test.yml`,
        line: 21,
        uses: `actions/setup-python@${pythonRef}`,
        action: "actions/setup-python",
        ref: pythonRef,
        classification: "MUTABLE",
        ownerType: "official",
        rawLine: `      - uses: actions/setup-python@${pythonRef}`,
      },
      {
        workflow: `${root}/.github/workflows/publish.yml`,
        line: 12,
        uses: "actions/checkout@v4",
        action: "actions/checkout",
        ref: "v4",
        classification: "MUTABLE",
        ownerType: "official",
        rawLine: "      - uses: actions/checkout@v4",
      },
    ],
    counts: { total: 3, pinned: 0, mutable: 3, branch: 0, local: 0, official: 3, thirdParty: 0, docker: 0 },
    workflows: [`${root}/.github/workflows/test.yml`, `${root}/.github/workflows/publish.yml`],
    checkedAt: "2026-01-01T00:00:00.000Z",
  };
}

describe("SW-4: adapter normalization without a caller-supplied root", () => {
  it("strips the report's own recorded root from workflow paths", () => {
    const a = adaptActionpin(pinReport(ROOT_A, "v5"), "");
    const b = adaptActionpin(pinReport(ROOT_B, "v5"), "");
    assert.deepEqual(a.findings.map((f) => f.file), b.findings.map((f) => f.file));
    assert.equal(a.findings[0].file, ".github/workflows/test.yml");
    assert.deepEqual(a.findings.map((f) => f.identity), b.findings.map((f) => f.identity));
    assert.deepEqual(a.findings.map((f) => f.findingId), b.findings.map((f) => f.findingId));
  });

  it("suffix fallback: no recorded root anywhere still relativizes workflow paths", () => {
    const report = pinReport(ROOT_A, "v5");
    delete (report as Record<string, unknown>).path;
    const a = adaptActionpin(report, "");
    assert.equal(a.findings[0].file, ".github/workflows/test.yml");
  });

  it("an explicit caller root still wins over the recorded root", () => {
    const a = adaptActionpin(pinReport(ROOT_A, "v5"), ROOT_A);
    assert.equal(a.findings[0].file, ".github/workflows/test.yml");
  });
});

describe("SW-4: cross-path import diff", () => {
  let dir: string;
  let store: Store;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "tw-sw4-"));
    store = new Store(dir);
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("same repo from two absolute paths: zero churn for unchanged findings", () => {
    importReports(store, {
      repo: "encode/httpx",
      at: "2026-01-01T00:00:00.000Z",
      reports: [{ tool: "actionpin", report: pinReport(ROOT_A, "v5") }],
    });
    importReports(store, {
      repo: "encode/httpx",
      at: "2026-01-02T00:00:00.000Z",
      reports: [{ tool: "actionpin", report: pinReport(ROOT_B, "v5") }],
    });
    const diff = diffScans(store, "encode/httpx");
    assert.equal(diff.added.length, 0, JSON.stringify(diff.added.map((f) => f.identity)));
    assert.equal(diff.resolved.length, 0, JSON.stringify(diff.resolved.map((f) => f.identity)));
    assert.equal(diff.changed.length, 0);
    // Two distinct findings: checkout appears in two workflow files.
    assert.equal(diff.unchangedCount, 3);
    assert.equal(diff.refEvents.length, 0);
  });

  it("a setup-python v5 -> v6 bump is one refEvent and one change, not churn", () => {
    importReports(store, {
      repo: "encode/httpx",
      at: "2026-01-01T00:00:00.000Z",
      reports: [{ tool: "actionpin", report: pinReport(ROOT_A, "v5") }],
    });
    importReports(store, {
      repo: "encode/httpx",
      at: "2026-01-02T00:00:00.000Z",
      reports: [{ tool: "actionpin", report: pinReport(ROOT_B, "v6") }],
    });
    const diff = diffScans(store, "encode/httpx");
    assert.equal(diff.added.length, 0, JSON.stringify(diff.added.map((f) => f.identity)));
    assert.equal(diff.resolved.length, 0, JSON.stringify(diff.resolved.map((f) => f.identity)));
    assert.equal(diff.changed.length, 1);
    assert.match(diff.changed[0].identity, /setup-python/);
    assert.ok(diff.changed[0].changes.some((c) => c.includes("ref: v5 -> v6")), JSON.stringify(diff.changed[0].changes));
    assert.equal(diff.refEvents.length, 1);
    assert.equal(diff.refEvents[0].oldRef, "v5");
    assert.equal(diff.refEvents[0].newRef, "v6");
    assert.equal(diff.refEvents[0].kind, "ref-move");
    assert.equal(diff.unchangedCount, 2);
  });
});
