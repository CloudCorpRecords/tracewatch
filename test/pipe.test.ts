/**
 * Pipe regression tests for the factory emit contract (FACTORY-NOTES.md).
 *
 * Node stdout on a pipe is asynchronous: console.log() followed by
 * process.exit() truncates output at exactly 65,536 bytes while still
 * exiting 0 (actionpin P-001, hookcheck P-017, injectcheck P-021; one
 * shared emit pattern). tracewatch ships the flush-aware emit helper
 * from day one, and these tests spawn the real CLI with piped stdio:
 * a report larger than 200 KiB must arrive whole and parseable, and an
 * early-closing reader must yield exit 141 or SIGPIPE, never 0.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SHA = "11bd71901bbe5b1630ceea73d27597364c9af683";

let dir: string;
let storeDir: string;

interface CliResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[], opts: { destroyStdoutOnFirstChunk?: boolean } = {}): Promise<CliResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["--import", "tsx", "src/cli.ts", ...args], {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (d: Buffer) => {
      if (opts.destroyStdoutOnFirstChunk) {
        child.stdout.destroy();
        return;
      }
      out += d.toString("utf8");
    });
    child.stderr.on("data", (d: Buffer) => {
      err += d.toString("utf8");
    });
    child.on("error", rejectPromise);
    child.on("close", (code, signal) => resolvePromise({ code, signal, stdout: out, stderr: err }));
  });
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "tracewatch-pipe-"));
  storeDir = join(dir, "store");
  const actions = Array.from({ length: 4000 }, (_, i) => ({
    workflow: "/repos/big/.github/workflows/ci.yml",
    line: i + 1,
    uses: `actions/checkout@${SHA}`,
    action: `actions/checkout-${i}`,
    ref: SHA,
    classification: "PINNED",
    ownerType: "official",
    rawLine: `      - uses: actions/checkout@${SHA}`,
  }));
  const report = {
    path: "/repos/big",
    verdict: "PINNED",
    actions,
    counts: { total: 4000, pinned: 4000, mutable: 0, branch: 0, local: 0, official: 4000, thirdParty: 0, docker: 0 },
    workflows: ["/repos/big/.github/workflows/ci.yml"],
    checkedAt: "2026-01-01T00:00:00.000Z",
  };
  writeFileSync(join(dir, "big-report.json"), JSON.stringify(report), "utf8");
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("pipe contract", () => {
  it("a >200 KiB findings report arrives whole through a pipe and parses", async () => {
    const imp = await runCli(["import", "big", "--report", `actionpin=${join(dir, "big-report.json")}`, "--store", storeDir]);
    assert.equal(imp.code, 0, imp.stderr);
    const res = await runCli(["findings", "big", "--status", "all", "--json", "--store", storeDir]);
    assert.equal(res.code, 0, res.stderr);
    assert.ok(res.stdout.length > 200 * 1024, `expected >200 KiB through the pipe, got ${res.stdout.length}`);
    const parsed = JSON.parse(res.stdout) as unknown[];
    assert.equal(parsed.length, 4000);
  });

  it("an early-closing reader never sees exit 0", async () => {
    const imp = await runCli(["import", "big", "--report", `actionpin=${join(dir, "big-report.json")}`, "--store", storeDir]);
    assert.equal(imp.code, 0, imp.stderr);
    const res = await runCli(["findings", "big", "--status", "all", "--json", "--store", storeDir], { destroyStdoutOnFirstChunk: true });
    assert.ok(res.code === 141 || res.signal === "SIGPIPE", `expected 141 or SIGPIPE, got code=${res.code} signal=${res.signal}`);
  });

  it("the human renderer is byte-identical to the in-process render through a pipe", async () => {
    const imp = await runCli(["import", "big", "--report", `actionpin=${join(dir, "big-report.json")}`, "--store", storeDir]);
    assert.equal(imp.code, 0, imp.stderr);
    const res = await runCli(["report", "big", "--store", storeDir]);
    assert.equal(res.code, 0, res.stderr);
    const { Store } = await import("../src/store.js");
    const { repoHealth } = await import("../src/report.js");
    const { renderHealth } = await import("../src/render.js");
    const expected = `${renderHealth(repoHealth(new Store(storeDir), "big"))}\n`;
    assert.equal(res.stdout, expected);
  });
});
