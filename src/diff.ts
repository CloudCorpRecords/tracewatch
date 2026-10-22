/**
 * Scan diffing. Two scans of one repo are compared by finding identity:
 *
 * - NEW: identity only in the later scan
 * - RESOLVED: identity only in the earlier scan
 * - CHANGED: identity in both, but the findingId or severity moved
 *   (content edit, severity regrade, or, for actionpin, a ref move)
 *
 * Action ref moves are first-class: a pin regression (PINNED to MUTABLE
 * or BRANCH), a pin improvement, or a bare ref move (the tj-actions
 * shape, where the ref under a name changed) each produce a RefEvent
 * with both values spelled out. Output ordering is by identity
 * everywhere, so the same store state always renders the same diff.
 */
import type { Store } from "./store.js";
import { TOOLS, type ChangedFinding, type FindingObs, type RefEvent, type ScanDiff, type ScanRecord } from "./types.js";

function refEventFor(before: FindingObs, after: FindingObs, scan: ScanRecord): RefEvent | undefined {
  if (before.tool !== "actionpin" || after.tool !== "actionpin") return undefined;
  const oldRef = String(before.data.ref ?? "");
  const newRef = String(after.data.ref ?? "");
  const oldClass = String(before.data.classification ?? "");
  const newClass = String(after.data.classification ?? "");
  if (oldRef === newRef && oldClass === newClass) return undefined;
  let kind: RefEvent["kind"] = "ref-move";
  if (oldClass === "PINNED" && newClass !== "PINNED") kind = "pin-regression";
  else if (newClass === "PINNED" && oldClass !== "PINNED") kind = "pin-improvement";
  return {
    identity: after.identity,
    file: after.file,
    action: String(after.data.action ?? after.file),
    oldRef,
    newRef,
    oldClassification: oldClass,
    newClassification: newClass,
    kind,
    scanId: scan.scanId,
    at: scan.at,
  };
}

function describeChanges(before: FindingObs, after: FindingObs): string[] {
  const changes: string[] = [];
  if (before.severity !== after.severity) changes.push(`severity: ${before.severity} -> ${after.severity}`);
  if (before.rule !== after.rule) changes.push(`rule: ${before.rule} -> ${after.rule}`);
  if (before.tool === "actionpin" && after.tool === "actionpin") {
    if (before.data.ref !== after.data.ref) changes.push(`ref: ${String(before.data.ref)} -> ${String(after.data.ref)}`);
    if (before.data.classification !== after.data.classification) {
      changes.push(`classification: ${String(before.data.classification)} -> ${String(after.data.classification)}`);
    }
  }
  if (before.tool === "hookcheck" && after.tool === "hookcheck" && before.data.command !== after.data.command) {
    changes.push("command changed");
  }
  if (before.tool === "injectcheck" && after.tool === "injectcheck" && before.excerpt !== after.excerpt) {
    changes.push("matched content changed");
  }
  if (changes.length === 0 && before.findingId !== after.findingId) changes.push("content changed");
  return changes;
}

export function diffObs(
  repo: string,
  fromScan: ScanRecord | null,
  toScan: ScanRecord,
  fromObs: FindingObs[],
  toObs: FindingObs[],
): ScanDiff {
  const fromById = new Map(fromObs.map((o) => [o.identity, o]));
  const toById = new Map(toObs.map((o) => [o.identity, o]));
  const added: FindingObs[] = [];
  const resolved: FindingObs[] = [];
  const changed: ChangedFinding[] = [];
  const refEvents: RefEvent[] = [];
  let unchangedCount = 0;

  for (const [identity, after] of toById) {
    const before = fromById.get(identity);
    if (!before) {
      added.push(after);
      continue;
    }
    if (before.findingId === after.findingId && before.severity === after.severity) {
      unchangedCount++;
      continue;
    }
    const refEvent = refEventFor(before, after, toScan);
    if (refEvent) refEvents.push(refEvent);
    changed.push({ identity, before, after, changes: describeChanges(before, after), refEvent });
  }
  for (const [identity, before] of fromById) {
    if (!toById.has(identity)) resolved.push(before);
  }

  const byIdentity = (a: { identity: string }, b: { identity: string }) => a.identity.localeCompare(b.identity);
  added.sort(byIdentity);
  resolved.sort(byIdentity);
  changed.sort(byIdentity);
  refEvents.sort(byIdentity);

  const verdictMoves = TOOLS.map((tool) => ({
    tool,
    from: fromScan?.tools[tool]?.verdict ?? null,
    to: toScan.tools[tool]?.verdict ?? null,
  })).filter((m) => m.from !== m.to);

  return {
    repo,
    from: fromScan ? { scanId: fromScan.scanId, at: fromScan.at } : null,
    to: { scanId: toScan.scanId, at: toScan.at },
    added,
    resolved,
    changed,
    unchangedCount,
    refEvents,
    verdictMoves,
  };
}

/** Diff two scans of a repo by id; defaults to the last two scans. */
export function diffScans(store: Store, repo: string, fromId?: string, toId?: string): ScanDiff {
  const scans = store.scans(repo);
  if (scans.length === 0) throw new Error(`no scans recorded for repo "${repo}"`);
  const to = toId ? store.scanById(toId) : scans[scans.length - 1];
  if (!to || to.repo !== repo) throw new Error(`scan "${toId}" not found for repo "${repo}"`);
  let from: ScanRecord | null = null;
  if (fromId) {
    from = store.scanById(fromId) ?? null;
    if (!from || from.repo !== repo) throw new Error(`scan "${fromId}" not found for repo "${repo}"`);
  } else {
    const idx = scans.findIndex((s) => s.scanId === to.scanId);
    from = idx > 0 ? scans[idx - 1] : null;
  }
  return diffObs(
    repo,
    from,
    to,
    from ? store.observations(from.scanId) : [],
    store.observations(to.scanId),
  );
}

/** Every ref event across consecutive scan pairs, oldest first. */
export function allRefEvents(store: Store, repo: string): RefEvent[] {
  const scans = store.scans(repo);
  const events: RefEvent[] = [];
  for (let i = 1; i < scans.length; i++) {
    const d = diffObs(repo, scans[i - 1], scans[i], store.observations(scans[i - 1].scanId), store.observations(scans[i].scanId));
    events.push(...d.refEvents);
  }
  return events;
}
