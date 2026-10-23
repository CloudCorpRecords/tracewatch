#!/usr/bin/env node
/**
 * tracewatch CLI.
 *
 *   tracewatch ingest <path> [--name <repo>] [--github <owner/repo>] [--tools a,b,c] [--json]
 *   tracewatch import <repo> --report <tool>=<file> [--report ...] [--path <p>] [--at <ISO>] [--json]
 *   tracewatch diff <repo> [--from <scanId>] [--to <scanId>] [--json]
 *   tracewatch blame <repo> (--finding <id> | --rule <rule> --file <path>) [--path <clone>] [--offline] [--json]
 *   tracewatch report <repo> [--json]
 *   tracewatch findings <repo> [--tool <t>] [--severity <s>] [--status open|resolved|all] [--json]
 *   tracewatch watch <path-or-owner/repo> [--path <clone>] [--interval <s>] [--once] [--max-minutes <n>] [--alerts <file>]
 *   tracewatch mcp
 *   tracewatch --version
 *
 * Every command accepts --store <dir> (default ~/.tracewatch or
 * TRACEWATCH_STORE). Exit codes: 0 success / no changes, 1 a diff found
 * changes, 2 usage error or total failure, 141 when the reader closed
 * the output pipe before the report was delivered.
 *
 * Every report goes through emit(), which waits for stdout to flush
 * before the exit code takes effect: the factory emit contract in
 * FACTORY-NOTES.md. Calling process.exit() right after console.log()
 * truncates piped output past one pipe buffer (64 KiB on Linux) while
 * still exiting 0, which is how agents and CI silently lose reports.
 */
import { readFileSync } from "node:fs";
import {
  VERSION,
  Store,
  defaultStoreDir,
  diffScans,
  explainFinding,
  importReports,
  ingestPath,
  renderDiff,
  renderFindings,
  renderHealth,
  renderProvenance,
  renderScanSummary,
  repoHealth,
  watch,
  TOOLS,
  type ToolName,
} from "./core.js";

function exitBrokenPipe(): never {
  process.exit(141);
}

process.stdout.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EPIPE") exitBrokenPipe();
  throw err;
});

/** Write one full report and resolve only after stdout has flushed it. */
async function emit(text: string, code: number): Promise<void> {
  process.exitCode = code;
  await new Promise<void>((resolve, reject) => {
    process.stdout.write(`${text}\n`, (err) => {
      if (!err) {
        resolve();
        return;
      }
      if ((err as NodeJS.ErrnoException).code === "EPIPE") exitBrokenPipe();
      reject(err);
    });
  });
}

function usage(): never {
  console.error(`Usage:
  tracewatch ingest <path> [--name <repo>] [--github <owner/repo>] [--tools a,b,c] [--json]
  tracewatch import <repo> --report <tool>=<file> [--report ...] [--path <p>] [--at <ISO>] [--json]
  tracewatch diff <repo> [--from <scanId>] [--to <scanId>] [--json]
  tracewatch blame <repo> (--finding <id> | --rule <rule> --file <path>) [--path <clone>] [--offline] [--json]
  tracewatch report <repo> [--json]
  tracewatch findings <repo> [--tool <t>] [--severity <s>] [--status open|resolved|all] [--json]
  tracewatch watch <path-or-owner/repo> [--path <clone>] [--interval <s>] [--once] [--max-minutes <n>] [--alerts <file>]
  tracewatch mcp
  tracewatch --version
  (every command accepts --store <dir>)`);
  process.exit(2);
}

function flagValue(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : undefined;
}

function flagValues(args: string[], name: string): string[] {
  const out: string[] = [];
  for (let i = 0; i + 1 < args.length; i++) if (args[i] === name) out.push(args[i + 1]);
  return out;
}

function has(args: string[], name: string): boolean {
  return args.includes(name);
}

function positional(args: string[], skipFlagsWithValues: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (skipFlagsWithValues.includes(a)) {
      i++;
      continue;
    }
    if (a.startsWith("--")) continue;
    out.push(a);
  }
  return out;
}

const VALUE_FLAGS = ["--name", "--github", "--tools", "--store", "--report", "--path", "--at", "--from", "--to", "--finding", "--rule", "--file", "--tool", "--severity", "--status", "--interval", "--max-minutes", "--alerts"];

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const [cmd, ...rest] = argv;
  if (cmd === "--version" || cmd === "-v" || cmd === "version") {
    console.log(VERSION);
    return;
  }
  if (cmd === "mcp") {
    await import("./mcp.js");
    return;
  }
  if (!cmd) usage();

  const store = new Store(flagValue(argv, "--store") ?? defaultStoreDir());
  const json = has(argv, "--json");

  try {
    if (cmd === "ingest") {
      const [target] = positional(rest, VALUE_FLAGS);
      if (!target) usage();
      const toolsArg = flagValue(rest, "--tools");
      const tools = toolsArg
        ? (toolsArg.split(",").map((s) => s.trim()).filter(Boolean) as ToolName[])
        : undefined;
      if (tools && tools.some((t) => !TOOLS.includes(t))) {
        console.error(`error: unknown tool in --tools (known: ${TOOLS.join(", ")})`);
        process.exitCode = 2;
        return;
      }
      const result = await ingestPath(store, target, {
        name: flagValue(rest, "--name"),
        github: flagValue(rest, "--github"),
        tools,
      });
      const allFailed = result.runs.length > 0 && result.runs.every((r) => r.info.status === "error");
      const text = json ? JSON.stringify({ scan: result.record, findings: result.observations }, null, 2) : renderScanSummary(result);
      await emit(text, allFailed ? 2 : 0);
    } else if (cmd === "import") {
      const [repo] = positional(rest, VALUE_FLAGS);
      const reportArgs = flagValues(rest, "--report");
      if (!repo || reportArgs.length === 0) usage();
      const reports = reportArgs.map((spec) => {
        const eq = spec.indexOf("=");
        if (eq <= 0) usage();
        const tool = spec.slice(0, eq) as ToolName;
        if (!TOOLS.includes(tool)) {
          console.error(`error: unknown tool "${spec.slice(0, eq)}" in --report (known: ${TOOLS.join(", ")})`);
          process.exit(2);
        }
        const file = spec.slice(eq + 1);
        return { tool, report: JSON.parse(readFileSync(file, "utf8")) as unknown };
      });
      const result = importReports(store, {
        repo,
        path: flagValue(rest, "--path"),
        github: flagValue(rest, "--github"),
        at: flagValue(rest, "--at"),
        reports,
      });
      const text = json ? JSON.stringify({ scan: result.record, findings: result.observations }, null, 2) : renderScanSummary(result);
      await emit(text, 0);
    } else if (cmd === "diff") {
      const [repo] = positional(rest, VALUE_FLAGS);
      if (!repo) usage();
      const diff = diffScans(store, repo, flagValue(rest, "--from"), flagValue(rest, "--to"));
      const changed = diff.added.length + diff.resolved.length + diff.changed.length > 0;
      await emit(json ? JSON.stringify(diff, null, 2) : renderDiff(diff), changed ? 1 : 0);
    } else if (cmd === "blame") {
      const [repo] = positional(rest, VALUE_FLAGS);
      if (!repo) usage();
      let id = flagValue(rest, "--finding");
      if (!id) {
        const rule = flagValue(rest, "--rule");
        const file = flagValue(rest, "--file");
        if (!rule || !file) usage();
        const match = store
          .trackedFindings(repo)
          .filter((t) => t.latest.rule === rule && t.latest.file === file)
          .sort((a, b) => b.lastSeenAt.localeCompare(a.lastSeenAt))[0];
        if (!match) {
          console.error(`error: no tracked finding for rule ${rule} in ${file} on repo "${repo}"`);
          process.exitCode = 2;
          return;
        }
        id = match.latest.findingId;
      }
      const explained = await explainFinding(store, repo, id, {
        path: flagValue(rest, "--path"),
        offline: has(rest, "--offline"),
      });
      if (!explained) {
        console.error(`error: finding "${id}" not found on repo "${repo}"`);
        process.exitCode = 2;
        return;
      }
      await emit(json ? JSON.stringify(explained.provenance, null, 2) : renderProvenance(explained.provenance), 0);
    } else if (cmd === "report") {
      const [repo] = positional(rest, VALUE_FLAGS);
      if (!repo) usage();
      const health = repoHealth(store, repo);
      await emit(json ? JSON.stringify(health, null, 2) : renderHealth(health), 0);
    } else if (cmd === "findings") {
      const [repo] = positional(rest, VALUE_FLAGS);
      if (!repo) usage();
      const tool = flagValue(rest, "--tool");
      const severity = flagValue(rest, "--severity");
      const status = flagValue(rest, "--status") ?? "open";
      const tracked = store
        .trackedFindings(repo)
        .filter((t) => (tool ? t.latest.tool === tool : true))
        .filter((t) => (severity ? t.latest.severity === severity : true))
        .filter((t) => (status === "all" ? true : t.status === status));
      await emit(json ? JSON.stringify(tracked, null, 2) : renderFindings(repo, tracked), 0);
    } else if (cmd === "watch") {
      const [target] = positional(rest, VALUE_FLAGS);
      if (!target) usage();
      await watch({
        store,
        target,
        name: flagValue(rest, "--name"),
        path: flagValue(rest, "--path"),
        intervalSec: Number(flagValue(rest, "--interval") ?? 60),
        once: has(rest, "--once"),
        maxMinutes: flagValue(rest, "--max-minutes") ? Number(flagValue(rest, "--max-minutes")) : undefined,
        alertsFile: flagValue(rest, "--alerts"),
      });
    } else {
      usage();
    }
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
  }
}

void main();
