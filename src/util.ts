/**
 * Small deterministic helpers: hashing, stable IDs, path normalization,
 * and time math. Everything here is pure so diffs and reports built on it
 * are reproducible from the same store state.
 */
import { createHash } from "node:crypto";
import { isAbsolute, relative, sep } from "node:path";

export function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** Content signature for a finding: hash of its defining content parts. */
export function signatureOf(parts: string[]): string {
  return sha256(parts.join("\n"));
}

export function makeIdentity(tool: string, location: string, rule: string): string {
  return `${tool}|${location}|${rule}`;
}

export function makeFindingId(tool: string, rule: string, location: string, signature: string): string {
  return `tw_${sha256(`${tool}|${rule}|${location}|${signature}`).slice(0, 16)}`;
}

export function makeScanId(repo: string, at: string, findingIds: string[]): string {
  return `sc_${sha256(`${repo}|${at}|${[...findingIds].sort().join(",")}`).slice(0, 12)}`;
}

/** Collapse all whitespace runs so trivial reflows keep one signature. */
export function collapseWs(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

/**
 * The scan root a report records about itself: actionpin and
 * hookcheck reports carry it as `path`, injectcheck as `target`.
 * Returns "" when the report records no absolute root.
 */
export function reportRootOf(report: unknown): string {
  if (typeof report !== "object" || report === null) return "";
  const raw = report as Record<string, unknown>;
  for (const key of ["path", "target"]) {
    const v = raw[key];
    if (typeof v === "string" && isAbsolute(v)) return v;
  }
  return "";
}

/**
 * Normalize a file path from a tool report to repo-relative form. Reports
 * may carry absolute paths (actionpin echoes the scanned path); anything
 * under the scan root is relativized, separators become forward slashes.
 *
 * SW-4: when no root covers an absolute path (an imported report whose
 * recorded root was never consulted, a caller root from a different
 * checkout), fall back to the repo-relative suffix at the
 * `.github/` anchor: workflows always live at <root>/.github/workflows,
 * so everything from `.github/` on is the repo-relative path regardless
 * of where the repo was checked out. Paths with no anchor are left
 * unchanged rather than guessed at.
 */
export function normalizePath(p: string, root?: string): string {
  let out = p;
  if (root && isAbsolute(out)) {
    const rel = relative(root, out);
    if (!rel.startsWith("..")) out = rel;
  }
  if (isAbsolute(out)) {
    const anchor = out.split(sep).join("/").match(/(?:^|\/)\.github\/(.*)$/);
    if (anchor) out = `.github/${anchor[1]}`;
  }
  return out.split(sep).join("/");
}

export function median(nums: number[]): number | null {
  if (nums.length === 0) return null;
  const sorted = [...nums].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[mid] : Math.round((sorted[mid - 1] + sorted[mid]) / 2);
}

export function formatDuration(ms: number | null): string {
  if (ms === null || !Number.isFinite(ms)) return "n/a";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)} s`;
  const m = s / 60;
  if (m < 60) return `${m.toFixed(1)} min`;
  const h = m / 60;
  if (h < 48) return `${h.toFixed(1)} h`;
  return `${(h / 24).toFixed(1)} d`;
}
