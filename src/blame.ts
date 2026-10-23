/**
 * Blame: root-cause provenance for one tracked finding.
 *
 * Evidence is labeled, never blended:
 *
 * - CONFIRMED: the introducing commit from `git log -S` (pickaxe) on the
 *   finding's own needle in the local clone (for multi-line content
 *   whose reported form is not literal file text, such as a dedented
 *   workflow run block, on one of the finding's own lines, proven by
 *   the same pickaxe scoped to the finding's file); the current-line commit
 *   from `git blame`; PR association from the GitHub API (commits/{sha}/
 *   pulls) through the ghapi helper; ref history and first/last seen
 *   from the tracewatch store itself.
 * - INFERRED: circumstantial statements, each written as one.
 * - NOT ESTABLISHED: whatever could not be proven, with the reason
 *   (no clone, no remote, API unreachable). Provenance is never guessed.
 */
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { runCapture } from "./ingest.js";
import { blameLine, logPickaxe, parseGithubSlug, remoteSlug } from "./git.js";
import type { Store } from "./store.js";
import type { FindingObs, Provenance, PullRef, TrackedFinding } from "./types.js";
import { collapseWs } from "./util.js";

export const GHAPI = process.env.TRACEWATCH_GHAPI ?? `${process.env.HOME ?? ""}/workspace/custom-connectors/custom.github-pat/bin/ghapi.py`;

function needleFor(obs: FindingObs): string {
  if (obs.tool === "hookcheck") return String(obs.data.command ?? obs.excerpt ?? "");
  if (obs.tool === "actionpin") return String(obs.data.uses ?? obs.excerpt ?? "");
  // A depguard finding is about a dependency: the dependency name is
  // literal text in the manifest, so git log -S on the name finds the
  // commits that touched that dependency line. Repo-level findings
  // have no dependency; their evidence prose is not file text, so
  // they honestly establish nothing by pickaxe.
  if (obs.tool === "depguard") return String(obs.data.dependency ?? "");
  if (obs.tool === "mcpvet") return collapseWs(String(obs.data.evidence ?? obs.excerpt ?? "")).slice(0, 80);
  return collapseWs(String(obs.data.excerpt ?? obs.excerpt ?? "")).slice(0, 80);
}

/**
 * Pickaxe candidates for a finding, most faithful first.
 *
 * The primary needle is the finding's own content string. That string
 * is not always literal file text: hookcheck reports the command of a
 * workflow run step dedented, one line per step line, while the file
 * on disk indents every one of those lines under the step. A multi-line
 * needle therefore never occurs literally in the committed file, and
 * `git log -S` on it finds nothing even when one commit plainly added
 * the whole file. Each individual line of the command, trimmed, does
 * occur literally (as a substring of the indented file line), so when
 * the primary needle misses, fall back to the finding's own lines,
 * longest first because the longest line is the most distinctive.
 * Every candidate is still proven by the same pickaxe, scoped to the
 * finding's file, so a hit is the same content proof as before; only
 * the needle's granularity changes. If no candidate hits, the finding
 * stays NOT ESTABLISHED.
 */
function needleCandidates(obs: FindingObs): string[] {
  const primary = needleFor(obs);
  if (!primary) return [];
  const candidates = [primary];
  const raw =
    obs.tool === "hookcheck"
      ? String(obs.data.command ?? obs.excerpt ?? "")
      : obs.tool === "actionpin"
        ? String(obs.data.uses ?? obs.excerpt ?? "")
        : obs.tool === "depguard"
          ? String(obs.data.dependency ?? "")
          : obs.tool === "mcpvet"
            ? String(obs.data.evidence ?? obs.excerpt ?? "")
            : String(obs.data.excerpt ?? obs.excerpt ?? "");
  const lines = new Map<string, void>();
  for (const source of [raw, primary]) {
    for (const line of source.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (trimmed.length >= 8) lines.set(trimmed);
    }
  }
  const sorted = [...lines.keys()].sort((a, b) => b.length - a.length);
  for (const line of sorted) {
    if (!candidates.includes(line)) candidates.push(line);
  }
  return candidates;
}

async function pullsForCommit(slug: string, sha: string): Promise<PullRef[] | null> {
  if (!existsSync(GHAPI)) return null;
  const res = await runCapture("python3", [GHAPI, "GET", `/repos/${slug}/commits/${sha}/pulls`], 30000);
  if (res.code !== 0 || !res.stdout.includes("HTTP 200")) return null;
  const body = res.stdout.slice(res.stdout.indexOf("\n") + 1);
  try {
    const arr = JSON.parse(body) as Record<string, unknown>[];
    if (Array.isArray(arr)) {
      return arr.map((p) => ({
        number: Number(p.number),
        title: String(p.title ?? ""),
        url: String(p.html_url ?? ""),
        state: String(p.state ?? ""),
      }));
    }
  } catch {
    // Helper output is truncated at 4000 chars; fall back to field extraction.
  }
  const out: PullRef[] = [];
  const re = /"number":\s*(\d+)[\s\S]{0,800}?"html_url":\s*"([^"]+)"[\s\S]{0,400}?"title":\s*"([^"]*)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    out.push({ number: Number(m[1]), url: m[2], title: m[3], state: "unknown" });
  }
  return out.length > 0 ? out : null;
}

function refHistory(store: Store, repo: string, identity: string): Provenance["confirmed"]["refHistory"] {
  const obs = store.findings(repo).filter((o) => o.identity === identity && o.tool === "actionpin");
  if (obs.length === 0) return undefined;
  const scanAt = new Map(store.scans(repo).map((s) => [s.scanId, s.at]));
  const runs: NonNullable<Provenance["confirmed"]["refHistory"]> = [];
  for (const o of obs) {
    const ref = String(o.data.ref ?? "");
    const classification = String(o.data.classification ?? "");
    const last = runs[runs.length - 1];
    if (last && last.ref === ref && last.classification === classification) {
      last.lastScanId = o.scanId;
      last.lastAt = scanAt.get(o.scanId) ?? last.lastAt;
    } else {
      runs.push({
        ref,
        classification,
        firstScanId: o.scanId,
        firstAt: scanAt.get(o.scanId) ?? "",
        lastScanId: o.scanId,
        lastAt: scanAt.get(o.scanId) ?? "",
      });
    }
  }
  return runs;
}

export async function blameFinding(
  store: Store,
  repo: string,
  tracked: TrackedFinding,
  opts: { path?: string; offline?: boolean } = {},
): Promise<Provenance> {
  const obs = tracked.latest;
  const prov: Provenance = {
    repo,
    finding: obs,
    status: tracked.status,
    firstSeenAt: tracked.firstSeenAt,
    lastSeenAt: tracked.lastSeenAt,
    confirmed: {},
    inferred: [],
    notEstablished: [],
  };

  const history = refHistory(store, repo, obs.identity);
  if (history && history.length > 0) prov.confirmed.refHistory = history;

  const dataSource = obs.data.source as { kind?: string; ref?: string; url?: string } | undefined;
  if (dataSource && dataSource.kind) {
    prov.confirmed.source = { kind: dataSource.kind, ref: String(dataSource.ref ?? ""), url: dataSource.url };
  }

  const scans = store.scans(repo);
  const recordedPath = [...scans].reverse().find((s) => s.path)?.path;
  const clonePath = opts.path ?? recordedPath;
  if (!clonePath || !existsSync(clonePath)) {
    prov.notEstablished.push(
      "git provenance not established: no local clone path is recorded for this repo (ingest a local path, or pass a clone path)",
    );
    if (!prov.confirmed.source && obs.tool === "injectcheck") {
      prov.notEstablished.push("text source not established: the ingest recorded no issue/PR or file origin beyond the scan target");
    }
    return prov;
  }
  const cwd = resolve(clonePath);

  const candidates = needleCandidates(obs);
  if (candidates.length > 0) {
    let introducing: Provenance["confirmed"]["introducingCommit"];
    for (const candidate of candidates) {
      const commits = await logPickaxe(cwd, candidate, obs.file);
      if (commits.length > 0) {
        introducing = commits[commits.length - 1];
        break;
      }
    }
    if (introducing) {
      prov.confirmed.introducingCommit = introducing;
    } else {
      prov.notEstablished.push(
        `introducing commit not established: git log -S found no commit introducing the needle in ${obs.file} (the content may predate the clone's history or live in an uncommitted state)`,
      );
    }
  }

  if (obs.line !== undefined) {
    const lineCommit = await blameLine(cwd, obs.file, obs.line);
    if (lineCommit) prov.confirmed.currentLineCommit = lineCommit;
  }

  const intro = prov.confirmed.introducingCommit;
  const line = prov.confirmed.currentLineCommit;
  if (intro && line && intro.sha !== line.sha) {
    prov.inferred.push(
      `the finding's content first appeared in ${intro.sha.slice(0, 12)}, but the current line was last rewritten by ${line.sha.slice(0, 12)}; the later commit touched the line without introducing the content`,
    );
  }

  if (intro && !opts.offline) {
    const slug = scans.find((s) => s.github)?.github ?? (await remoteSlug(cwd));
    if (slug && parseGithubSlug(slug)) {
      const pulls = await pullsForCommit(slug, intro.sha);
      if (pulls !== null) {
        prov.confirmed.pullRequests = pulls;
        if (pulls.length === 0) {
          prov.inferred.push("the GitHub API lists no pull request for the introducing commit (direct push, or a PR from a deleted fork)");
        }
      } else {
        prov.notEstablished.push("PR association not established: the GitHub API helper did not answer for the introducing commit");
      }
    } else {
      prov.notEstablished.push("PR association not established: the clone has no GitHub remote");
    }
  } else if (intro && opts.offline) {
    prov.notEstablished.push("PR association not established: offline mode");
  }

  return prov;
}

/** explain_finding bundle: the tracked finding, its history, and its provenance. */
export async function explainFinding(
  store: Store,
  repo: string,
  idOrPrefix: string,
  opts: { path?: string; offline?: boolean } = {},
): Promise<{ tracked: TrackedFinding; provenance: Provenance } | null> {
  const tracked = store.findFinding(repo, idOrPrefix);
  if (!tracked) return null;
  const provenance = await blameFinding(store, repo, tracked, opts);
  return { tracked, provenance };
}
