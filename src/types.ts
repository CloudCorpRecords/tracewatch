/**
 * tracewatch types.
 *
 * tracewatch is the Security Wave's memory: it ingests the JSON reports of
 * hookcheck, actionpin, injectcheck, mcpvet, depguard, and flowcheck,
 * stores them as timestamped scan records, and tracks every finding
 * across scans under a stable ID so a finding can be diffed, aged, and
 * blamed to the commit that introduced it.
 * Every record here is plain JSON: the store is append-only JSONL files the
 * operator can grep by hand.
 */

export type ToolName = "hookcheck" | "actionpin" | "injectcheck" | "mcpvet" | "depguard" | "flowcheck";

export const TOOLS: ToolName[] = ["hookcheck", "actionpin", "injectcheck", "mcpvet", "depguard", "flowcheck"];

/** Single severity scale every tool's native scale is mapped onto. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface ToolScanInfo {
  /** Version of the tool that produced the report, e.g. "0.1.14". */
  version: string;
  /** The tool's own verdict string, e.g. "COMPROMISED-PATTERN". */
  verdict: string;
  counts: Record<string, number>;
  status: "ok" | "error";
  error?: string;
  /**
   * Tool-specific scan context a later diff needs to interpret the
   * findings. depguard fills this with its diff context: the base the
   * head was compared against (a git ref, a directory path, or null in
   * snapshot mode), the head path, and the run mode, so a diff can say
   * what changed against what instead of presenting bare findings.
   */
  context?: Record<string, unknown>;
}

export interface ScanRecord {
  scanId: string;
  /** Repo key the scan belongs to (a name, or an owner/repo slug). */
  repo: string;
  /** ISO timestamp of the ingest. */
  at: string;
  source: "run" | "import" | "watch";
  /** Local path that was scanned, when known. */
  path?: string;
  /** GitHub slug (owner/repo) when known. */
  github?: string;
  /** git HEAD of the target at scan time, when it is a repo. */
  headSha?: string | null;
  tools: Partial<Record<ToolName, ToolScanInfo>>;
  warnings: string[];
}

/**
 * One observation of one finding in one scan. The store keeps every
 * observation; a finding's status (open, resolved, changed) is always
 * derived from the observation series, never stored as mutable state.
 */
export interface FindingObs {
  /** tw_ + 16 hex: hash of tool, rule, normalized location, content signature. */
  findingId: string;
  /** Durable match key: tool | location | rule. Stable across content edits. */
  identity: string;
  scanId: string;
  repo: string;
  tool: ToolName;
  rule: string;
  severity: Severity;
  /** File path normalized relative to the scan root (or a source label). */
  file: string;
  line?: number;
  detail: string;
  excerpt?: string;
  /** Content signature the findingId was built from (sha256 hex). */
  signature: string;
  /** Tool-specific payload diff and blame need (command text, uses/ref, ...). */
  data: Record<string, unknown>;
}

/** A finding plus its derived status across the whole store. */
export interface TrackedFinding {
  identity: string;
  /** Most recent observation. */
  latest: FindingObs;
  firstSeenAt: string;
  lastSeenAt: string;
  firstScanId: string;
  lastScanId: string;
  status: "open" | "resolved";
  /** Scan time at which the finding was first absent after being present. */
  resolvedAt?: string;
  /** Distinct findingIds over time: more than one means the content changed. */
  versions: number;
}

export interface DetectionRecord {
  at: string;
  repo: string;
  kind: "issue" | "pr" | "tree" | "file";
  /** Issue/PR number, file path, or commit SHA the content arrived as. */
  sourceRef: string;
  /** The content's own creation timestamp (issue created_at, commit time, file birth/mtime). */
  createdAt: string;
  timeToDetectMs: number;
  scanId?: string;
  findingIds: string[];
}

export interface AlertRecord {
  at: string;
  repo: string;
  kind: "new-finding" | "changed-finding" | "ref-event" | "detection" | "watch-note";
  message: string;
  findingId?: string;
  detection?: DetectionRecord;
}

export interface RefEvent {
  identity: string;
  file: string;
  action: string;
  oldRef: string;
  newRef: string;
  oldClassification: string;
  newClassification: string;
  kind: "ref-move" | "pin-regression" | "pin-improvement";
  /** Scan the event was observed in (the "to" scan of the diff). */
  scanId: string;
  at: string;
}

export interface ChangedFinding {
  identity: string;
  before: FindingObs;
  after: FindingObs;
  /** Human-readable field moves, e.g. "severity: medium -> high". */
  changes: string[];
  refEvent?: RefEvent;
}

export interface ScanDiff {
  repo: string;
  from: { scanId: string; at: string } | null;
  to: { scanId: string; at: string };
  added: FindingObs[];
  resolved: FindingObs[];
  changed: ChangedFinding[];
  unchangedCount: number;
  refEvents: RefEvent[];
  verdictMoves: { tool: ToolName; from: string | null; to: string | null }[];
}

export interface CommitInfo {
  sha: string;
  author: string;
  date: string;
  subject: string;
}

export interface PullRef {
  number: number;
  title: string;
  url: string;
  state: string;
}

export interface Provenance {
  repo: string;
  finding: FindingObs;
  status: "open" | "resolved";
  firstSeenAt: string;
  lastSeenAt: string;
  confirmed: {
    /** Earliest commit whose diff introduced the finding's needle (git log -S). */
    introducingCommit?: CommitInfo;
    /** Commit git blame assigns to the finding's current line at HEAD. */
    currentLineCommit?: CommitInfo;
    pullRequests?: PullRef[];
    /** For action ref moves: first-seen and last-seen refs from the store itself. */
    refHistory?: { ref: string; classification: string; firstScanId: string; firstAt: string; lastScanId: string; lastAt: string }[];
    source?: { kind: string; ref: string; url?: string };
  };
  /** Statements supported only circumstantially; labeled, never merged with confirmed. */
  inferred: string[];
  /** What could not be established, with the reason. Never guessed around. */
  notEstablished: string[];
}

export interface HealthReport {
  repo: string;
  scanCount: number;
  firstScanAt: string | null;
  lastScanAt: string | null;
  verdictTrend: { scanId: string; at: string; verdicts: Partial<Record<ToolName, string>> }[];
  open: { total: number; byTool: Record<string, number>; bySeverity: Record<string, number> };
  resolvedCount: number;
  meanTimeOpenMs: number | null;
  refEvents: RefEvent[];
  detections: {
    count: number;
    medianMs: number | null;
    maxMs: number | null;
    byKind: Record<string, { count: number; medianMs: number | null; maxMs: number | null }>;
  };
}
