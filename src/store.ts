/**
 * The store: append-only JSONL files under one directory.
 *
 *   scans.jsonl      one ScanRecord per ingest
 *   findings.jsonl   one FindingObs per finding per scan
 *   detections.jsonl one DetectionRecord per watch detection
 *   alerts.jsonl     one AlertRecord per emitted alert
 *   watch-state.json checkpoints for watch mode (rewritten atomically)
 *
 * Reads tolerate a torn final line (a crash mid-append) by skipping any
 * line that does not parse; appends are single write() calls per record.
 * Finding status is derived from the observation series on every read,
 * never stored, so the store cannot disagree with itself.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { AlertRecord, DetectionRecord, FindingObs, ScanRecord, TrackedFinding } from "./types.js";

export function defaultStoreDir(): string {
  return process.env.TRACEWATCH_STORE ?? join(homedir(), ".tracewatch");
}

function readJsonl<T>(file: string): T[] {
  if (!existsSync(file)) return [];
  const out: T[] = [];
  for (const line of readFileSync(file, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed) as T);
    } catch {
      // Torn or hand-edited line: skip it rather than failing every read.
    }
  }
  return out;
}

export class Store {
  readonly dir: string;

  constructor(dir: string) {
    this.dir = dir;
  }

  private file(name: string): string {
    return join(this.dir, name);
  }

  private ensure(): void {
    mkdirSync(this.dir, { recursive: true });
  }

  private append(name: string, record: unknown): void {
    this.ensure();
    appendFileSync(this.file(name), `${JSON.stringify(record)}\n`, "utf8");
  }

  appendScan(rec: ScanRecord): void {
    this.append("scans.jsonl", rec);
  }

  appendFindings(obs: FindingObs[]): void {
    for (const o of obs) this.append("findings.jsonl", o);
  }

  appendDetection(rec: DetectionRecord): void {
    this.append("detections.jsonl", rec);
  }

  appendAlert(rec: AlertRecord): void {
    this.append("alerts.jsonl", rec);
  }

  scans(repo?: string): ScanRecord[] {
    const all = readJsonl<ScanRecord>(this.file("scans.jsonl"));
    return repo ? all.filter((s) => s.repo === repo) : all;
  }

  findings(repo?: string): FindingObs[] {
    const all = readJsonl<FindingObs>(this.file("findings.jsonl"));
    return repo ? all.filter((f) => f.repo === repo) : all;
  }

  detections(repo?: string): DetectionRecord[] {
    const all = readJsonl<DetectionRecord>(this.file("detections.jsonl"));
    return repo ? all.filter((d) => d.repo === repo) : all;
  }

  alerts(repo?: string): AlertRecord[] {
    const all = readJsonl<AlertRecord>(this.file("alerts.jsonl"));
    return repo ? all.filter((a) => a.repo === repo) : all;
  }

  repos(): string[] {
    return [...new Set(this.scans().map((s) => s.repo))].sort();
  }

  scanById(scanId: string): ScanRecord | undefined {
    return this.scans().find((s) => s.scanId === scanId);
  }

  latestScan(repo: string): ScanRecord | undefined {
    const list = this.scans(repo);
    return list[list.length - 1];
  }

  observations(scanId: string): FindingObs[] {
    return this.findings().filter((f) => f.scanId === scanId);
  }

  /**
   * Derive every tracked finding for a repo: status, first/last seen,
   * resolution time, and content version count. Deterministic: output is
   * sorted by identity, and scan order is store append order.
   */
  trackedFindings(repo: string): TrackedFinding[] {
    const scanList = this.scans(repo);
    const scanAt = new Map(scanList.map((s) => [s.scanId, s.at]));
    const scanIndex = new Map(scanList.map((s, i) => [s.scanId, i]));
    const byIdentity = new Map<string, FindingObs[]>();
    for (const obs of this.findings(repo)) {
      const arr = byIdentity.get(obs.identity) ?? [];
      arr.push(obs);
      byIdentity.set(obs.identity, arr);
    }
    const latest = scanList[scanList.length - 1];
    const out: TrackedFinding[] = [];
    for (const [identity, obsList] of byIdentity) {
      const sorted = [...obsList].sort(
        (a, b) => (scanIndex.get(a.scanId) ?? 0) - (scanIndex.get(b.scanId) ?? 0),
      );
      const first = sorted[0];
      const last = sorted[sorted.length - 1];
      const isOpen = latest !== undefined && last.scanId === latest.scanId;
      let resolvedAt: string | undefined;
      if (!isOpen && latest) {
        const lastIdx = scanIndex.get(last.scanId) ?? 0;
        const next = scanList[lastIdx + 1];
        if (next) resolvedAt = next.at;
      }
      out.push({
        identity,
        latest: last,
        firstSeenAt: scanAt.get(first.scanId) ?? first.scanId,
        lastSeenAt: scanAt.get(last.scanId) ?? last.scanId,
        firstScanId: first.scanId,
        lastScanId: last.scanId,
        status: isOpen ? "open" : "resolved",
        resolvedAt,
        versions: new Set(sorted.map((o) => o.findingId)).size,
      });
    }
    return out.sort((a, b) => a.identity.localeCompare(b.identity));
  }

  /** Find one tracked finding by full or prefix findingId, or by identity. */
  findFinding(repo: string, idOrPrefix: string): TrackedFinding | undefined {
    const tracked = this.trackedFindings(repo);
    return (
      tracked.find((t) => t.latest.findingId === idOrPrefix) ??
      tracked.find((t) => t.identity === idOrPrefix) ??
      tracked.find((t) => t.latest.findingId.startsWith(idOrPrefix) && idOrPrefix.length >= 8)
    );
  }

  readWatchState<T>(): T | null {
    const file = this.file("watch-state.json");
    if (!existsSync(file)) return null;
    try {
      return JSON.parse(readFileSync(file, "utf8")) as T;
    } catch {
      return null;
    }
  }

  writeWatchState(state: unknown): void {
    this.ensure();
    const tmp = `${this.file("watch-state.json")}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`, "utf8");
    renameSync(tmp, this.file("watch-state.json"));
  }
}
