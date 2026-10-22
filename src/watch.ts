/**
 * Watch mode: poll a target and scan new content on arrival, recording
 * time-to-detect for every detection.
 *
 * Local mode watches a directory: new or changed text files are scanned
 * with injectcheck the poll they appear in, and a git HEAD move triggers
 * a full ingest plus diff, with alerts for new/changed findings and ref
 * events. GitHub mode watches an owner/repo slug through the ghapi
 * helper: new issues and PRs are scanned on arrival, and a HEAD move is
 * recorded (and scanned too, when a local clone path is supplied).
 *
 * State checkpoints to watch-state.json after every cycle, so a restart
 * resumes from the last poll instead of re-alerting history. Polling is
 * conservative (default 60 s, two API calls per GitHub cycle) and every
 * detection records TTD = detected-at minus the content's own creation
 * timestamp. Nothing here guesses: an API answer that cannot be parsed
 * is logged as a watch note and retried next cycle, never faked.
 */
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, extname, join, relative, resolve } from "node:path";
import { tmpdir } from "node:os";
import { adaptReport, type AdaptedReport } from "./adapters.js";
import { diffScans } from "./diff.js";
import { commitTime, headSha } from "./git.js";
import { GHAPI, } from "./blame.js";
import { ingestPath, recordScan, runCapture, runInjectcheckFile, toolVersion, type IngestResult } from "./ingest.js";
import type { Store } from "./store.js";
import type { AlertRecord, DetectionRecord, FindingObs } from "./types.js";
import { makeFindingId, makeIdentity } from "./util.js";

export interface FileMark {
  mtimeMs: number;
  size: number;
  birthtimeMs: number;
  hash?: string;
}

export interface RepoWatchState {
  target: string;
  lastHead?: string | null;
  snapshot?: Record<string, FileMark>;
  issuesSeen?: Record<string, string>;
  issueNoteAt?: string;
}

export interface WatchStateFile {
  repos: Record<string, RepoWatchState>;
}

const SKIP_DIRS = new Set([".git", "node_modules", "dist", ".tracewatch", "coverage", ".next", "target"]);
const TEXT_EXTS = new Set([".md", ".markdown", ".txt", ".rst", ".mdx", ".adoc"]);

export function snapshotTree(root: string): Record<string, FileMark> {
  const out: Record<string, FileMark> = {};
  const walk = (dir: string): void => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) walk(full);
      } else if (e.isFile()) {
        try {
          const st = statSync(full);
          const mark: FileMark = { mtimeMs: st.mtimeMs, size: st.size, birthtimeMs: st.birthtimeMs };
          if (st.size <= 2 * 1024 * 1024) {
            mark.hash = createHash("sha1").update(readFileSync(full)).digest("hex");
          }
          out[relative(root, full).split("\\").join("/")] = mark;
        } catch {
          // Vanished mid-walk: next poll sees the settled state.
        }
      }
    }
  };
  walk(root);
  return out;
}

export interface WatchDeps {
  scanFile: (path: string) => Promise<AdaptedReport | null>;
  ingest: (store: Store, path: string, opts: { name?: string; source?: "watch" }) => Promise<IngestResult>;
  ghGet: (path: string) => Promise<string | null>;
  now: () => Date;
  /** Tool version lookup; injectable so tests never spawn real tools. */
  version?: (tool: "injectcheck") => Promise<string>;
}

export const defaultDeps: WatchDeps = {
  scanFile: (p) => runInjectcheckFile(p),
  ingest: (store, path, opts) => ingestPath(store, path, { name: opts.name, source: "watch" }),
  ghGet: async (path) => {
    if (!existsSync(GHAPI)) return null;
    const res = await runCapture("python3", [GHAPI, "GET", path], 30000);
    return res.code === 0 && res.stdout.includes("HTTP 200") ? res.stdout : null;
  },
  now: () => new Date(),
};

export interface WatchContext {
  store: Store;
  deps: WatchDeps;
  emit: (alert: AlertRecord) => void;
}

function loadState(store: Store): WatchStateFile {
  return store.readWatchState<WatchStateFile>() ?? { repos: {} };
}

function saveState(store: Store, state: WatchStateFile): void {
  store.writeWatchState(state);
}

async function recordTextScan(
  ctx: WatchContext,
  repo: string,
  adapted: AdaptedReport,
  extra: { path?: string; github?: string },
): Promise<{ scanId: string; observations: FindingObs[] }> {
  const version = ctx.deps.version ? await ctx.deps.version("injectcheck") : await toolVersion("injectcheck");
  const result = recordScan(ctx.store, repo, "watch", [adapted], {
    injectcheck: { version, verdict: adapted.verdict, counts: adapted.counts, status: "ok" },
  }, extra);
  return { scanId: result.record.scanId, observations: result.observations };
}

async function diffAlerts(ctx: WatchContext, repo: string, at: string): Promise<AlertRecord[]> {
  const alerts: AlertRecord[] = [];
  try {
    const diff = diffScans(ctx.store, repo);
    for (const f of diff.added) {
      alerts.push({ at, repo, kind: "new-finding", findingId: f.findingId, message: `NEW ${f.tool} ${f.rule} (${f.severity}) in ${f.file}: ${f.detail}` });
    }
    for (const c of diff.changed) {
      alerts.push({ at, repo, kind: "changed-finding", findingId: c.after.findingId, message: `CHANGED ${c.after.tool} ${c.after.rule} in ${c.after.file}: ${c.changes.join("; ")}` });
    }
    for (const ev of diff.refEvents) {
      alerts.push({
        at,
        repo,
        kind: "ref-event",
        findingId: diff.changed.find((c) => c.identity === ev.identity)?.after.findingId,
        message: `${ev.kind.toUpperCase()} ${ev.action} in ${ev.file}: ref ${ev.oldRef} -> ${ev.newRef} (${ev.oldClassification} -> ${ev.newClassification})`,
      });
    }
  } catch {
    // Fewer than two scans: nothing to diff yet.
  }
  return alerts;
}

/** One local poll cycle. Returns the alerts emitted this cycle. */
export async function pollLocalOnce(
  ctx: WatchContext,
  repo: string,
  targetPath: string,
): Promise<AlertRecord[]> {
  const { store, deps } = ctx;
  const abs = resolve(targetPath);
  const state = loadState(store);
  const entry: RepoWatchState = state.repos[repo] ?? { target: abs };
  const alerts: AlertRecord[] = [];
  const now = deps.now();
  const at = now.toISOString();

  const snap = snapshotTree(abs);
  const head = await headSha(abs);

  if (!entry.snapshot) {
    // Baseline: record state, and take a baseline scan if none exists.
    entry.snapshot = snap;
    entry.lastHead = head;
    state.repos[repo] = entry;
    saveState(store, state);
    if (store.scans(repo).length === 0) {
      await deps.ingest(store, abs, { name: repo, source: "watch" });
    }
    return alerts;
  }

  const prev = entry.snapshot;
  const changedFiles: { rel: string; mark: FileMark; added: boolean }[] = [];
  for (const [rel, mark] of Object.entries(snap)) {
    const before = prev[rel];
    if (!before) changedFiles.push({ rel, mark, added: true });
    else if (before.hash !== mark.hash || (before.hash === undefined && (before.mtimeMs !== mark.mtimeMs || before.size !== mark.size))) {
      changedFiles.push({ rel, mark, added: false });
    }
  }

  for (const { rel, mark, added } of changedFiles) {
    if (!TEXT_EXTS.has(extname(rel).toLowerCase())) continue;
    const adapted = await deps.scanFile(join(abs, rel));
    if (!adapted || adapted.findings.length === 0) continue;
    const { scanId, observations } = await recordTextScan(ctx, repo, adapted, { path: abs });
    const createdMs = added && mark.birthtimeMs > 0 ? mark.birthtimeMs : mark.mtimeMs;
    const detection: DetectionRecord = {
      at,
      repo,
      kind: "file",
      sourceRef: rel,
      createdAt: new Date(createdMs).toISOString(),
      timeToDetectMs: Math.max(0, now.getTime() - createdMs),
      scanId,
      findingIds: observations.map((o) => o.findingId),
    };
    store.appendDetection(detection);
    const alert: AlertRecord = {
      at,
      repo,
      kind: "detection",
      message: `DETECTION file ${rel}: ${observations.length} injectcheck finding(s), time-to-detect ${detection.timeToDetectMs} ms`,
      detection,
    };
    alerts.push(alert);
    ctx.emit(alert);
  }

  if (head && entry.lastHead && head !== entry.lastHead) {
    const result = await deps.ingest(store, abs, { name: repo, source: "watch" });
    const createdAt = (await commitTime(abs, "HEAD")) ?? at;
    const diffAlertsList = await diffAlerts(ctx, repo, at);
    const detection: DetectionRecord = {
      at,
      repo,
      kind: "tree",
      sourceRef: head,
      createdAt,
      timeToDetectMs: Math.max(0, now.getTime() - Date.parse(createdAt)),
      scanId: result.record.scanId,
      findingIds: diffAlertsList.map((a) => a.findingId).filter((x): x is string => Boolean(x)),
    };
    store.appendDetection(detection);
    for (const a of diffAlertsList) {
      alerts.push(a);
      ctx.emit(a);
    }
    const detAlert: AlertRecord = {
      at,
      repo,
      kind: "detection",
      message: `DETECTION tree ${head.slice(0, 12)}: re-scanned, ${diffAlertsList.length} change alert(s), time-to-detect ${detection.timeToDetectMs} ms`,
      detection,
    };
    alerts.push(detAlert);
    ctx.emit(detAlert);
  }

  entry.snapshot = snap;
  entry.lastHead = head;
  state.repos[repo] = entry;
  saveState(store, state);
  return alerts;
}

interface GhIssue {
  number: number;
  title: string;
  body: string;
  created_at: string;
  html_url: string;
  isPr: boolean;
}

/** One GitHub poll cycle (issues/PRs + HEAD). Returns alerts emitted. */
export async function pollGithubOnce(
  ctx: WatchContext,
  slug: string,
  opts: { path?: string } = {},
): Promise<AlertRecord[]> {
  const { store, deps } = ctx;
  const alerts: AlertRecord[] = [];
  const now = deps.now();
  const at = now.toISOString();
  const state = loadState(store);
  const entry: RepoWatchState = state.repos[slug] ?? { target: slug, issuesSeen: {} };
  entry.issuesSeen ??= {};
  const firstContact = Object.keys(entry.issuesSeen).length === 0 && !entry.lastHead;

  // HEAD move.
  const commitsOut = await deps.ghGet(`/repos/${slug}/commits?per_page=1`);
  const headShaRemote = commitsOut?.match(/"sha":\s*"([0-9a-f]{40})"/)?.[1] ?? null;
  const headDate = commitsOut?.match(/"date":\s*"([^"]+)"/)?.[1] ?? null;
  if (headShaRemote && entry.lastHead && headShaRemote !== entry.lastHead) {
    const detection: DetectionRecord = {
      at,
      repo: slug,
      kind: "tree",
      sourceRef: headShaRemote,
      createdAt: headDate ?? at,
      timeToDetectMs: Math.max(0, now.getTime() - Date.parse(headDate ?? at)),
      findingIds: [],
    };
    if (opts.path) {
      const result = await deps.ingest(store, opts.path, { name: slug, source: "watch" });
      detection.scanId = result.record.scanId;
      const list = await diffAlerts(ctx, slug, at);
      detection.findingIds = list.map((a) => a.findingId).filter((x): x is string => Boolean(x));
      for (const a of list) {
        alerts.push(a);
        ctx.emit(a);
      }
    }
    store.appendDetection(detection);
    const alert: AlertRecord = {
      at,
      repo: slug,
      kind: "detection",
      message: `DETECTION tree ${headShaRemote.slice(0, 12)} on ${slug}: time-to-detect ${detection.timeToDetectMs} ms${opts.path ? "" : " (no local clone supplied, tree recorded but not scanned)"}`,
      detection,
    };
    alerts.push(alert);
    ctx.emit(alert);
  }
  if (headShaRemote) entry.lastHead = headShaRemote;

  // Issues and PRs.
  const issuesOut = await deps.ghGet(`/repos/${slug}/issues?state=all&per_page=10&sort=created&direction=desc`);
  let issues: GhIssue[] | null = null;
  if (issuesOut) {
    const body = issuesOut.slice(issuesOut.indexOf("\n") + 1);
    try {
      const arr = JSON.parse(body) as Record<string, unknown>[];
      if (Array.isArray(arr)) {
        issues = arr.map((i) => ({
          number: Number(i.number),
          title: String(i.title ?? ""),
          body: String(i.body ?? ""),
          created_at: String(i.created_at ?? ""),
          html_url: String(i.html_url ?? ""),
          isPr: "pull_request" in i,
        }));
      }
    } catch {
      issues = null;
    }
  }
  if (issues === null) {
    if (!entry.issueNoteAt || Date.parse(at) - Date.parse(entry.issueNoteAt) > 3600000) {
      const note: AlertRecord = {
        at,
        repo: slug,
        kind: "watch-note",
        message: "issue poll skipped this cycle: the API helper response could not be parsed in full (long responses are truncated by the helper); will retry next cycle. The CI event-driven pattern in the README is the recommended production path for issue scanning.",
      };
      alerts.push(note);
      ctx.emit(note);
      entry.issueNoteAt = at;
    }
  } else {
    const fresh = issues
      .filter((i) => i.number > 0 && !(String(i.number) in (entry.issuesSeen ?? {})))
      .sort((a, b) => a.number - b.number);
    const baseline = firstContact;
    for (const issue of fresh) {
      (entry.issuesSeen as Record<string, string>)[String(issue.number)] = issue.created_at;
      if (baseline) continue; // First contact: record history silently, do not scan the backlog.
      const tmpDir = join(tmpdir(), `tracewatch-issue-${slug.replace("/", "-")}-${issue.number}`);
      mkdirSync(tmpDir, { recursive: true });
      const tmpFile = join(tmpDir, "body.md");
      writeFileSync(tmpFile, issue.body, "utf8");
      const adaptedRaw = await deps.scanFile(tmpFile);
      if (!adaptedRaw || adaptedRaw.findings.length === 0) continue;
      const label = `${issue.isPr ? "pr" : "issue"} #${issue.number}`;
      const adapted: AdaptedReport = {
        ...adaptedRaw,
        findings: adaptedRaw.findings.map((f) => {
          const location = label;
          const identity = makeIdentity("injectcheck", location, f.rule);
          return {
            ...f,
            file: label,
            identity,
            findingId: makeFindingId("injectcheck", f.rule, location, f.signature),
            data: { ...f.data, source: { kind: issue.isPr ? "pr" : "issue", ref: String(issue.number), url: issue.html_url } },
          };
        }),
      };
      const { scanId, observations } = await recordTextScan(ctx, slug, adapted, { github: slug });
      const detection: DetectionRecord = {
        at,
        repo: slug,
        kind: issue.isPr ? "pr" : "issue",
        sourceRef: label,
        createdAt: issue.created_at || at,
        timeToDetectMs: Math.max(0, now.getTime() - Date.parse(issue.created_at || at)),
        scanId,
        findingIds: observations.map((o) => o.findingId),
      };
      store.appendDetection(detection);
      const alert: AlertRecord = {
        at,
        repo: slug,
        kind: "detection",
        message: `DETECTION ${label} on ${slug}: ${observations.length} injectcheck finding(s), time-to-detect ${detection.timeToDetectMs} ms`,
        detection,
      };
      alerts.push(alert);
      ctx.emit(alert);
    }
  }

  state.repos[slug] = entry;
  saveState(store, state);
  return alerts;
}

export interface WatchOptions {
  store: Store;
  target: string;
  /** Repo key override (default: directory basename, or the slug itself). */
  name?: string;
  path?: string;
  intervalSec?: number;
  once?: boolean;
  maxMinutes?: number;
  alertsFile?: string;
  deps?: WatchDeps;
  stderr?: (line: string) => void;
}

/** Run watch until stopped (SIGINT/SIGTERM), --once, or --max-minutes. */
export async function watch(opts: WatchOptions): Promise<{ cycles: number; alerts: number }> {
  const deps = opts.deps ?? defaultDeps;
  const intervalSec = Math.max(1, opts.intervalSec ?? 60);
  const isLocal = existsSync(opts.target) && statSync(opts.target).isDirectory();
  const repo = opts.name ?? (isLocal ? basename(resolve(opts.target)) : opts.target);
  const log = opts.stderr ?? ((l: string) => process.stderr.write(`${l}\n`));
  let alertCount = 0;
  const emit = (alert: AlertRecord): void => {
    alertCount++;
    opts.store.appendAlert(alert);
    const line = JSON.stringify(alert);
    process.stdout.write(`${line}\n`);
    if (opts.alertsFile) appendFileSync(opts.alertsFile, `${line}\n`, "utf8");
  };
  const ctx: WatchContext = { store: opts.store, deps, emit };

  let stopped = false;
  const onSignal = (): void => {
    stopped = true;
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  const deadline = opts.maxMinutes ? Date.now() + opts.maxMinutes * 60000 : null;
  log(`tracewatch watch: ${isLocal ? "local" : "github"} target ${opts.target}, interval ${intervalSec}s${opts.once ? ", single cycle" : ""}`);

  let cycles = 0;
  try {
    for (;;) {
      if (isLocal) await pollLocalOnce(ctx, repo, resolve(opts.target));
      else await pollGithubOnce(ctx, opts.target, { path: opts.path });
      cycles++;
      if (opts.once || stopped) break;
      if (deadline && Date.now() >= deadline) break;
      const until = Date.now() + intervalSec * 1000;
      while (!stopped && Date.now() < until && (!deadline || Date.now() < deadline)) {
        await new Promise((r) => setTimeout(r, Math.min(250, Math.max(1, until - Date.now()))));
      }
      if (stopped || (deadline && Date.now() >= deadline)) break;
    }
  } finally {
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
  }
  log(`tracewatch watch: stopped after ${cycles} cycle(s), ${alertCount} alert(s)`);
  return { cycles, alerts: alertCount };
}
