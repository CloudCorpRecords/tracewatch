/**
 * Health report: what the store knows about one repo over time.
 * Verdict trend, open findings by tool and severity, resolution speed
 * (mean time open, first-seen scan to the scan where a finding was
 * first absent), all ref events, and watch detection latency stats.
 * Pure derivation from the store, sorted everywhere, so identical store
 * state renders identical reports.
 */
import { allRefEvents } from "./diff.js";
import type { Store } from "./store.js";
import { TOOLS, type HealthReport } from "./types.js";
import { median } from "./util.js";

export function repoHealth(store: Store, repo: string): HealthReport {
  const scans = store.scans(repo);
  const tracked = store.trackedFindings(repo);
  const open = tracked.filter((t) => t.status === "open");
  const resolved = tracked.filter((t) => t.status === "resolved");

  const byTool: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const t of open) {
    byTool[t.latest.tool] = (byTool[t.latest.tool] ?? 0) + 1;
    bySeverity[t.latest.severity] = (bySeverity[t.latest.severity] ?? 0) + 1;
  }

  const openDurations: number[] = [];
  for (const t of resolved) {
    if (!t.resolvedAt) continue;
    const ms = Date.parse(t.resolvedAt) - Date.parse(t.firstSeenAt);
    if (Number.isFinite(ms) && ms >= 0) openDurations.push(ms);
  }
  const meanTimeOpenMs =
    openDurations.length > 0 ? Math.round(openDurations.reduce((a, b) => a + b, 0) / openDurations.length) : null;

  const detections = store.detections(repo);
  const ttd = detections.map((d) => d.timeToDetectMs);
  const byKind: HealthReport["detections"]["byKind"] = {};
  for (const kind of [...new Set(detections.map((d) => d.kind))].sort()) {
    const vals = detections.filter((d) => d.kind === kind).map((d) => d.timeToDetectMs);
    byKind[kind] = { count: vals.length, medianMs: median(vals), maxMs: vals.length ? Math.max(...vals) : null };
  }

  return {
    repo,
    scanCount: scans.length,
    firstScanAt: scans[0]?.at ?? null,
    lastScanAt: scans[scans.length - 1]?.at ?? null,
    verdictTrend: scans.map((s) => ({
      scanId: s.scanId,
      at: s.at,
      verdicts: Object.fromEntries(TOOLS.filter((t) => s.tools[t]).map((t) => [t, s.tools[t]?.verdict ?? ""])),
    })),
    open: { total: open.length, byTool, bySeverity },
    resolvedCount: resolved.length,
    meanTimeOpenMs,
    refEvents: allRefEvents(store, repo),
    detections: {
      count: detections.length,
      medianMs: median(ttd),
      maxMs: ttd.length ? Math.max(...ttd) : null,
      byKind,
    },
  };
}
