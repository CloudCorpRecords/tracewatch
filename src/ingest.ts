/**
 * Ingest: run the published Security Wave tools against a target, or import
 * report files, and store the result as one scan record plus one
 * observation per finding.
 *
 * Tools are child processes resolved in this order: the
 * TRACEWATCH_<TOOL>_CMD override, the tool on PATH, then
 * `npx -y @reneturcios/<tool>`. Their stdout is collected through a pipe
 * and parsed as JSON; a tool's exit code of 0 or 1 both mean "report
 * produced" (the tools exit 1 when their verdict is not clean), anything
 * else, or unparseable output, is recorded as a per-tool error on the
 * scan record. One tool failing never blocks the others.
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { adaptReport, type AdaptedReport } from "./adapters.js";
import { headSha, remoteSlug } from "./git.js";
import type { Store } from "./store.js";
import { TOOLS, type FindingObs, type ScanRecord, type ToolName, type ToolScanInfo } from "./types.js";
import { makeScanId } from "./util.js";

export interface ToolCommand {
  cmd: string;
  args: string[];
}

export function resolveToolCommand(tool: ToolName): ToolCommand {
  const override = process.env[`TRACEWATCH_${tool.toUpperCase()}_CMD`];
  if (override) {
    const parts = override.split(/\s+/).filter(Boolean);
    if (parts.length > 0) return { cmd: parts[0], args: parts.slice(1) };
  }
  for (const dir of (process.env.PATH ?? "").split(":")) {
    if (dir && existsSync(join(dir, tool))) return { cmd: tool, args: [] };
  }
  return { cmd: "npx", args: ["-y", `@reneturcios/${tool}`] };
}

interface Capture {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export function runCapture(cmd: string, args: string[], timeoutMs = 180000): Promise<Capture> {
  return new Promise((resolvePromise) => {
    const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    child.stdout.on("data", (d: Buffer) => {
      if (stdout.length < 64 * 1024 * 1024) stdout += d.toString("utf8");
    });
    child.stderr.on("data", (d: Buffer) => {
      if (stderr.length < 1024 * 1024) stderr += d.toString("utf8");
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      resolvePromise({ code: null, stdout, stderr: `${stderr}${err.message}`, timedOut });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolvePromise({ code, stdout, stderr, timedOut });
    });
  });
}

const versionCache = new Map<ToolName, string>();

export async function toolVersion(tool: ToolName): Promise<string> {
  const cached = versionCache.get(tool);
  if (cached) return cached;
  const { cmd, args } = resolveToolCommand(tool);
  const res = await runCapture(cmd, [...args, "--version"], 120000);
  const first = res.stdout.split("\n").map((s) => s.trim()).find((s) => /\d+\.\d+\.\d+/.test(s));
  const version = first ? (first.match(/\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?/)?.[0] ?? first) : "unknown";
  versionCache.set(tool, version);
  return version;
}

const SCAN_ARGS: Record<ToolName, (target: string) => string[]> = {
  hookcheck: (t) => ["scan", t, "--json"],
  actionpin: (t) => ["audit", t, "--json"],
  injectcheck: (t) => ["scan", t, "--json"],
  mcpvet: (t) => ["vet", t, "--json"],
  // depguard direct runs use its offline snapshot mode: the target is
  // checked on its own (base null), which still surfaces manifest and
  // lockfile findings. A full base/head comparison needs a base the
  // bare target does not name, so diff-context scans arrive by import
  // of a report produced with --base or --base-path (see README).
  depguard: (t) => ["check", t, "--json", "--offline"],
  flowcheck: (t) => ["audit", t, "--json"],
};

export interface ToolRun {
  tool: ToolName;
  info: ToolScanInfo;
  adapted: AdaptedReport | null;
}

export async function runTool(tool: ToolName, target: string): Promise<ToolRun> {
  const version = await toolVersion(tool);
  const { cmd, args } = resolveToolCommand(tool);
  const res = await runCapture(cmd, [...args, ...SCAN_ARGS[tool](target)]);
  const fail = (error: string): ToolRun => ({
    tool,
    info: { version, verdict: "ERROR", counts: {}, status: "error", error },
    adapted: null,
  });
  if (res.timedOut) return fail(`${tool} timed out`);
  const start = res.stdout.indexOf("{");
  if (start === -1) return fail(`${tool} produced no JSON report (exit ${res.code ?? "spawn error"})`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(res.stdout.slice(start));
  } catch {
    return fail(`${tool} report did not parse as JSON (exit ${res.code ?? "spawn error"})`);
  }
  const adapted = adaptReport(tool, parsed, target);
  return {
    tool,
    info: { version, verdict: adapted.verdict, counts: adapted.counts, status: "ok", context: adapted.context },
    adapted,
  };
}

/** Run injectcheck against a single text file (watch mode issue/file scans). */
export async function runInjectcheckFile(file: string): Promise<AdaptedReport | null> {
  const { cmd, args } = resolveToolCommand("injectcheck");
  const res = await runCapture(cmd, [...args, "file", file, "--json"], 120000);
  const start = res.stdout.indexOf("{");
  if (start === -1) return null;
  try {
    return adaptReport("injectcheck", JSON.parse(res.stdout.slice(start)), file);
  } catch {
    return null;
  }
}

export interface IngestResult {
  record: ScanRecord;
  observations: FindingObs[];
  runs: ToolRun[];
}

/** Stamp adapted reports into the store as one scan record. Exported for watch mode. */
export function recordScan(
  store: Store,
  repo: string,
  source: ScanRecord["source"],
  adaptedList: AdaptedReport[],
  infos: Partial<Record<ToolName, ToolScanInfo>>,
  extra: { path?: string; github?: string; headSha?: string | null; at?: string; warnings?: string[] },
): IngestResult {
  const at = extra.at ?? new Date().toISOString();
  const flat = adaptedList.flatMap((a) => a.findings);
  const scanId = makeScanId(repo, at, flat.map((f) => f.findingId));
  const record: ScanRecord = {
    scanId,
    repo,
    at,
    source,
    path: extra.path,
    github: extra.github,
    headSha: extra.headSha ?? null,
    tools: infos,
    warnings: [...(extra.warnings ?? []), ...adaptedList.flatMap((a) => a.warnings)],
  };
  const observations: FindingObs[] = flat.map((f) => ({ ...f, scanId, repo }));
  store.appendScan(record);
  store.appendFindings(observations);
  return { record, observations, runs: [] };
}

export async function ingestPath(
  store: Store,
  target: string,
  opts: { name?: string; github?: string; tools?: ToolName[]; source?: ScanRecord["source"] } = {},
): Promise<IngestResult> {
  const abs = resolve(target);
  const github = opts.github ?? (await remoteSlug(abs)) ?? undefined;
  const repo = opts.name ?? github ?? basename(abs);
  const head = await headSha(abs);
  const wanted = opts.tools ?? TOOLS;
  const runs = await Promise.all(wanted.map((t) => runTool(t, abs)));
  const infos: Partial<Record<ToolName, ToolScanInfo>> = {};
  const adaptedList: AdaptedReport[] = [];
  const warnings: string[] = [];
  for (const run of runs) {
    infos[run.tool] = run.info;
    if (run.adapted) adaptedList.push(run.adapted);
    if (run.info.status === "error") warnings.push(run.info.error ?? `${run.tool} failed`);
  }
  const result = recordScan(store, repo, opts.source ?? "run", adaptedList, infos, {
    path: abs,
    github,
    headSha: head,
    warnings,
  });
  return { ...result, runs };
}

export function importReports(
  store: Store,
  opts: {
    repo: string;
    path?: string;
    github?: string;
    at?: string;
    reports: { tool: ToolName; report: unknown }[];
  },
): IngestResult {
  const root = opts.path ? resolve(opts.path) : "";
  const adaptedList: AdaptedReport[] = [];
  const infos: Partial<Record<ToolName, ToolScanInfo>> = {};
  for (const { tool, report } of opts.reports) {
    const adapted = adaptReport(tool, report, root);
    adaptedList.push(adapted);
    infos[tool] = { version: "imported", verdict: adapted.verdict, counts: adapted.counts, status: "ok", context: adapted.context };
  }
  return recordScan(store, opts.repo, "import", adaptedList, infos, {
    path: opts.path ? resolve(opts.path) : undefined,
    github: opts.github,
    at: opts.at,
  });
}
