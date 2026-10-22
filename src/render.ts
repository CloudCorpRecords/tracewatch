/**
 * Human renderers. Deterministic: every line derives from store data,
 * sorted where the underlying structure is a set, and no wall-clock
 * "generated at" text appears anywhere, so identical store state renders
 * byte-identical output (acceptance T6).
 */
import type { IngestResult } from "./ingest.js";
import { SEVERITY_ORDER, type HealthReport, type Provenance, type ScanDiff, type TrackedFinding } from "./types.js";
import { formatDuration } from "./util.js";

export function renderScanSummary(result: IngestResult): string {
  const r = result.record;
  const lines: string[] = [];
  lines.push(`scan ${r.scanId} repo ${r.repo} at ${r.at} (source: ${r.source})`);
  if (r.headSha) lines.push(`head: ${r.headSha}`);
  const tools = Object.entries(r.tools).sort(([a], [b]) => a.localeCompare(b));
  if (tools.length === 0) lines.push("tools: none recorded");
  for (const [tool, info] of tools) {
    if (!info) continue;
    const counts = Object.entries(info.counts)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join(" ");
    lines.push(`  ${tool} ${info.version}: ${info.verdict}${info.status === "error" ? ` (ERROR: ${info.error ?? "failed"})` : ""}${counts ? ` [${counts}]` : ""}`);
  }
  lines.push(`findings recorded: ${result.observations.length}`);
  for (const w of r.warnings) lines.push(`warning: ${w}`);
  return lines.join("\n");
}

function obsLine(o: TrackedFinding["latest"]): string {
  const loc = o.line !== undefined ? `${o.file}:${o.line}` : o.file;
  return `  [${o.severity}] ${o.findingId} ${o.tool}/${o.rule} ${loc} - ${o.detail}`;
}

export function renderDiff(diff: ScanDiff): string {
  const lines: string[] = [];
  lines.push(`diff repo ${diff.repo}`);
  lines.push(`  from: ${diff.from ? `${diff.from.scanId} at ${diff.from.at}` : "(no earlier scan)"}`);
  lines.push(`  to:   ${diff.to.scanId} at ${diff.to.at}`);
  if (diff.verdictMoves.length > 0) {
    lines.push("verdict moves:");
    for (const m of diff.verdictMoves) lines.push(`  ${m.tool}: ${m.from ?? "(none)"} -> ${m.to ?? "(none)"}`);
  }
  lines.push(`new findings (${diff.added.length}):`);
  for (const o of diff.added) lines.push(obsLine(o));
  lines.push(`resolved findings (${diff.resolved.length}):`);
  for (const o of diff.resolved) lines.push(obsLine(o));
  lines.push(`changed findings (${diff.changed.length}):`);
  for (const c of diff.changed) {
    lines.push(obsLine(c.after));
    for (const change of c.changes) lines.push(`    ${change}`);
  }
  if (diff.refEvents.length > 0) {
    lines.push(`ref events (${diff.refEvents.length}):`);
    for (const ev of diff.refEvents) {
      lines.push(`  ${ev.kind}: ${ev.action} in ${ev.file}: ${ev.oldRef} -> ${ev.newRef} (${ev.oldClassification} -> ${ev.newClassification})`);
    }
  }
  lines.push(`unchanged: ${diff.unchangedCount}`);
  if (diff.added.length === 0 && diff.resolved.length === 0 && diff.changed.length === 0) {
    lines.push("no changes between these scans");
  }
  return lines.join("\n");
}

export function renderProvenance(prov: Provenance): string {
  const o = prov.finding;
  const lines: string[] = [];
  lines.push(`provenance for ${o.findingId} (${o.tool}/${o.rule})`);
  lines.push(`  repo: ${prov.repo}  status: ${prov.status}`);
  lines.push(`  location: ${o.line !== undefined ? `${o.file}:${o.line}` : o.file}`);
  lines.push(`  detail: ${o.detail}`);
  lines.push(`  first seen: ${prov.firstSeenAt}  last seen: ${prov.lastSeenAt}`);
  const c = prov.confirmed;
  lines.push("confirmed (evidence):");
  if (c.introducingCommit) {
    lines.push(`  introducing commit: ${c.introducingCommit.sha} by ${c.introducingCommit.author} on ${c.introducingCommit.date}`);
    lines.push(`    subject: ${c.introducingCommit.subject}`);
  }
  if (c.currentLineCommit) {
    lines.push(`  current line commit (git blame): ${c.currentLineCommit.sha} by ${c.currentLineCommit.author} on ${c.currentLineCommit.date}`);
    lines.push(`    subject: ${c.currentLineCommit.subject}`);
  }
  if (c.pullRequests) {
    if (c.pullRequests.length === 0) lines.push("  pull requests: none listed by the GitHub API for the introducing commit");
    for (const pr of c.pullRequests) lines.push(`  pull request: #${pr.number} ${pr.title} (${pr.state}) ${pr.url}`);
  }
  if (c.refHistory) {
    lines.push("  ref history (from the scan store):");
    for (const h of c.refHistory) {
      lines.push(`    ${h.ref} (${h.classification}) first ${h.firstAt} [${h.firstScanId}] last ${h.lastAt} [${h.lastScanId}]`);
    }
  }
  if (c.source) lines.push(`  content source: ${c.source.kind} ${c.source.ref}${c.source.url ? ` ${c.source.url}` : ""}`);
  if (!c.introducingCommit && !c.currentLineCommit && !c.pullRequests && !c.refHistory && !c.source) {
    lines.push("  (none)");
  }
  if (prov.inferred.length > 0) {
    lines.push("inferred (circumstantial, labeled as such):");
    for (const s of prov.inferred) lines.push(`  ${s}`);
  }
  if (prov.notEstablished.length > 0) {
    lines.push("not established:");
    for (const s of prov.notEstablished) lines.push(`  ${s}`);
  }
  return lines.join("\n");
}

export function renderHealth(h: HealthReport): string {
  const lines: string[] = [];
  lines.push(`health report: ${h.repo}`);
  lines.push(`scans: ${h.scanCount}${h.firstScanAt ? ` (${h.firstScanAt} to ${h.lastScanAt})` : ""}`);
  lines.push("verdict trend:");
  for (const t of h.verdictTrend) {
    const vs = Object.entries(t.verdicts)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join(" ");
    lines.push(`  ${t.at} ${t.scanId} ${vs}`);
  }
  lines.push(`open findings: ${h.open.total}`);
  for (const tool of Object.keys(h.open.byTool).sort()) lines.push(`  by tool ${tool}: ${h.open.byTool[tool]}`);
  for (const sev of SEVERITY_ORDER) {
    if (h.open.bySeverity[sev]) lines.push(`  by severity ${sev}: ${h.open.bySeverity[sev]}`);
  }
  lines.push(`resolved findings: ${h.resolvedCount}`);
  lines.push(`mean time open (resolved): ${h.meanTimeOpenMs === null ? "n/a (nothing resolved yet)" : formatDuration(h.meanTimeOpenMs)}`);
  lines.push(`ref events: ${h.refEvents.length}`);
  for (const ev of h.refEvents) {
    lines.push(`  ${ev.at} ${ev.kind}: ${ev.action} in ${ev.file}: ${ev.oldRef} -> ${ev.newRef}`);
  }
  lines.push(
    `detections: ${h.detections.count} (median time-to-detect ${formatDuration(h.detections.medianMs)}, max ${formatDuration(h.detections.maxMs)})`,
  );
  for (const [kind, s] of Object.entries(h.detections.byKind).sort(([a], [b]) => a.localeCompare(b))) {
    lines.push(`  ${kind}: ${s.count} (median ${formatDuration(s.medianMs)}, max ${formatDuration(s.maxMs)})`);
  }
  return lines.join("\n");
}

export function renderFindings(repo: string, tracked: TrackedFinding[]): string {
  const lines: string[] = [`findings for ${repo}: ${tracked.length}`];
  for (const t of tracked) {
    const o = t.latest;
    const loc = o.line !== undefined ? `${o.file}:${o.line}` : o.file;
    lines.push(
      `[${t.status}] ${o.findingId} ${o.tool}/${o.rule} (${o.severity}) ${loc} first ${t.firstSeenAt} last ${t.lastSeenAt}${t.versions > 1 ? ` versions ${t.versions}` : ""} - ${o.detail}`,
    );
  }
  return lines.join("\n");
}
