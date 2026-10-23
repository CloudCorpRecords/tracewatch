/**
 * Adapters: translate each tool's published JSON report shape into
 * tracewatch's normalized finding observations.
 *
 * The shapes consumed are the tools' public contracts, verified against
 * hookcheck 0.1.14, actionpin 0.1.6, injectcheck 0.1.13, mcpvet 0.1.1,
 * depguard 0.1.0, and flowcheck 0.1.0:
 *
 * - hookcheck: {verdict, findings: [{id, file, source, hook, command,
 *   line?, classification, rules, evidence}], counts, warnings}
 * - actionpin: {verdict, actions: [{workflow, line, uses, action, ref,
 *   classification, ownerType, rawLine}], counts}
 * - injectcheck: {verdict, findings: [{file, line, rule, severity,
 *   excerpt, detail}], counts, warnings}
 * - mcpvet: {verdict, kind, name, findings: [{rule, severity, file,
 *   line, evidence, detail}], counts, notes}
 * - flowcheck: {verdict, findings: [{rule, severity, file, line, job?,
 *   message}], counts (partly nested under bySeverity, flattened away),
 *   plans, caps}
 * - depguard: {verdict, path (the head), base (a git ref, a directory
 *   path, or null in snapshot mode), mode, changes: [{name, change
 *   (added, removed, changed), rangeFrom?, rangeTo?, versionFrom?,
 *   versionTo?, verdict, findings: [{rule, severity, source,
 *   evidence}]}], repoFindings: [{rule, severity, source, evidence}],
 *   counts, warnings}. depguard has no top-level findings array: its
 *   findings hang off the dependency changes they belong to, so the
 *   adapter flattens them and keeps the change and the scan-level diff
 *   context (base, head, mode) on every finding it produces.
 *
 * Adapters are pure and total: a malformed entry is skipped and counted
 * in the returned warnings, never thrown through, so one bad record can
 * not take down an ingest of the other tools.
 */
import type { FindingObs, Severity, ToolName } from "./types.js";
import { collapseWs, makeFindingId, makeIdentity, normalizePath, reportRootOf, signatureOf } from "./util.js";


/**
 * SW-4: the effective scan root for normalization. A caller-supplied
 * root wins; otherwise the root the report records about itself is
 * used (actionpin/hookcheck `path`, injectcheck `target`). Imported
 * reports arrive with no caller root, and stripping only a caller
 * root left actionpin's absolute workflow paths in finding identity,
 * so the same repo scanned from a different checkout churned every
 * actionpin finding in the diff and hid real ref moves.
 */
function effectiveRoot(report: unknown, root: string): string {
  return root || reportRootOf(report);
}

export type NormalizedFinding = Omit<FindingObs, "scanId" | "repo">;

export interface AdaptedReport {
  tool: ToolName;
  verdict: string;
  counts: Record<string, number>;
  findings: NormalizedFinding[];
  warnings: string[];
  /** Scan-level context for ToolScanInfo (depguard diff context). */
  context?: Record<string, unknown>;
}

type Raw = Record<string, unknown>;

function asObj(v: unknown): Raw | null {
  return typeof v === "object" && v !== null ? (v as Raw) : null;
}

function str(v: unknown, fallback = ""): string {
  return typeof v === "string" ? v : fallback;
}

function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function countsOf(raw: Raw): Record<string, number> {
  const c = asObj(raw.counts);
  const out: Record<string, number> = {};
  if (c) for (const [k, v] of Object.entries(c)) if (typeof v === "number") out[k] = v;
  return out;
}

const HOOK_SEVERITY: Record<string, Severity> = { RISKY: "high", UNKNOWN: "medium", SAFE: "low" };
const ACTION_SEVERITY: Record<string, Severity> = { BRANCH: "high", MUTABLE: "medium", PINNED: "info", LOCAL: "low" };
const INJECT_SEVERITY: Record<string, Severity> = { high: "high", medium: "medium", low: "low" };
/** mcpvet, depguard, and flowcheck all publish the shared factory scale. */
const FACTORY_SEVERITY: Record<string, Severity> = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info" };

export function adaptHookcheck(report: unknown, root: string): AdaptedReport {
  const raw = asObj(report) ?? {};
  const findings: NormalizedFinding[] = [];
  const warnings: string[] = (Array.isArray(raw.warnings) ? raw.warnings : []).map((w) => `hookcheck: ${String(w)}`);
  const list = Array.isArray(raw.findings) ? raw.findings : [];
  for (const entry of list) {
    const f = asObj(entry);
    if (!f) {
      warnings.push("hookcheck: skipped a malformed finding entry");
      continue;
    }
    const location = str(f.id, str(f.file, "unknown"));
    const rules = Array.isArray(f.rules) ? f.rules.map(String) : [];
    const rule = rules.length > 0 ? rules.join("+") : "inventory";
    const command = str(f.command);
    const signature = signatureOf([command]);
    findings.push({
      findingId: makeFindingId("hookcheck", rule, location, signature),
      identity: makeIdentity("hookcheck", location, rule),
      tool: "hookcheck",
      rule,
      severity: HOOK_SEVERITY[str(f.classification)] ?? "medium",
      file: normalizePath(str(f.file, location), effectiveRoot(report, root)),
      line: num(f.line),
      detail: str(f.evidence),
      excerpt: command ? command.slice(0, 200) : undefined,
      signature,
      data: { source: str(f.source), hook: str(f.hook), command, classification: str(f.classification) },
    });
  }
  return { tool: "hookcheck", verdict: str(raw.verdict, "UNKNOWN"), counts: countsOf(raw), findings, warnings };
}

export function adaptActionpin(report: unknown, root: string): AdaptedReport {
  const raw = asObj(report) ?? {};
  const findings: NormalizedFinding[] = [];
  const warnings: string[] = [];
  const list = Array.isArray(raw.actions) ? raw.actions : [];
  for (const entry of list) {
    const a = asObj(entry);
    if (!a) {
      warnings.push("actionpin: skipped a malformed action entry");
      continue;
    }
    const file = normalizePath(str(a.workflow), effectiveRoot(report, root));
    const action = str(a.action, str(a.uses));
    const uses = str(a.uses);
    const ref = str(a.ref);
    const classification = str(a.classification, "MUTABLE");
    const rule = "action-ref";
    const location = `${file}|${action}`;
    const signature = signatureOf([uses, ref, classification]);
    findings.push({
      findingId: makeFindingId("actionpin", rule, location, signature),
      identity: makeIdentity("actionpin", location, rule),
      tool: "actionpin",
      rule,
      severity: ACTION_SEVERITY[classification] ?? "medium",
      file,
      line: num(a.line),
      detail: `${uses} is ${classification.toLowerCase()} (${str(a.ownerType, "unknown")} action)`,
      excerpt: uses,
      signature,
      data: { action, uses, ref, classification, ownerType: str(a.ownerType) },
    });
  }
  return { tool: "actionpin", verdict: str(raw.verdict, "UNKNOWN"), counts: countsOf(raw), findings, warnings };
}

export function adaptInjectcheck(report: unknown, root: string): AdaptedReport {
  const raw = asObj(report) ?? {};
  const findings: NormalizedFinding[] = [];
  const warnings: string[] = (Array.isArray(raw.warnings) ? raw.warnings : []).map((w) => `injectcheck: ${String(w)}`);
  const list = Array.isArray(raw.findings) ? raw.findings : [];
  for (const entry of list) {
    const f = asObj(entry);
    if (!f) {
      warnings.push("injectcheck: skipped a malformed finding entry");
      continue;
    }
    const file = normalizePath(str(f.file, str(raw.target, "text")), effectiveRoot(report, root));
    const rule = str(f.rule, "unknown-rule");
    const excerpt = str(f.excerpt);
    const signature = signatureOf([collapseWs(excerpt)]);
    findings.push({
      findingId: makeFindingId("injectcheck", rule, file, signature),
      identity: makeIdentity("injectcheck", file, rule),
      tool: "injectcheck",
      rule,
      severity: INJECT_SEVERITY[str(f.severity)] ?? "low",
      file,
      line: num(f.line),
      detail: str(f.detail),
      excerpt: excerpt ? excerpt.slice(0, 200) : undefined,
      signature,
      data: { excerpt },
    });
  }
  return { tool: "injectcheck", verdict: str(raw.verdict, "UNKNOWN"), counts: countsOf(raw), findings, warnings };
}

export function adaptMcpvet(report: unknown, root: string): AdaptedReport {
  const raw = asObj(report) ?? {};
  const findings: NormalizedFinding[] = [];
  const warnings: string[] = (Array.isArray(raw.notes) ? raw.notes : []).map((w) => `mcpvet: ${String(w)}`);
  const list = Array.isArray(raw.findings) ? raw.findings : [];
  for (const entry of list) {
    const f = asObj(entry);
    if (!f) {
      warnings.push("mcpvet: skipped a malformed finding entry");
      continue;
    }
    const file = normalizePath(str(f.file, "unknown"), effectiveRoot(report, root));
    const rule = str(f.rule, "unknown-rule");
    const evidence = str(f.evidence);
    const signature = signatureOf([collapseWs(evidence), collapseWs(str(f.detail))]);
    findings.push({
      findingId: makeFindingId("mcpvet", rule, file, signature),
      identity: makeIdentity("mcpvet", file, rule),
      tool: "mcpvet",
      rule,
      severity: FACTORY_SEVERITY[str(f.severity)] ?? "low",
      file,
      line: num(f.line),
      detail: str(f.detail),
      excerpt: evidence ? evidence.slice(0, 200) : undefined,
      signature,
      data: { evidence, kind: str(raw.kind), name: str(raw.name) },
    });
  }
  return { tool: "mcpvet", verdict: str(raw.verdict, "UNKNOWN"), counts: countsOf(raw), findings, warnings };
}

export function adaptFlowcheck(report: unknown, root: string): AdaptedReport {
  const raw = asObj(report) ?? {};
  const findings: NormalizedFinding[] = [];
  const warnings: string[] = [];
  const list = Array.isArray(raw.findings) ? raw.findings : [];
  for (const entry of list) {
    const f = asObj(entry);
    if (!f) {
      warnings.push("flowcheck: skipped a malformed finding entry");
      continue;
    }
    const file = normalizePath(str(f.file, "unknown"), effectiveRoot(report, root));
    const rule = str(f.rule, "unknown-rule");
    const job = str(f.job);
    const message = str(f.message);
    // One workflow file can carry the same rule in several jobs; the job
    // is part of the location so those findings version separately,
    // the same way actionpin keys on the action name.
    const location = job ? `${file}|${job}` : file;
    const signature = signatureOf([collapseWs(message)]);
    findings.push({
      findingId: makeFindingId("flowcheck", rule, location, signature),
      identity: makeIdentity("flowcheck", location, rule),
      tool: "flowcheck",
      rule,
      severity: FACTORY_SEVERITY[str(f.severity)] ?? "low",
      file,
      line: num(f.line),
      detail: message,
      excerpt: message ? message.slice(0, 200) : undefined,
      signature,
      data: { job, message },
    });
  }
  return { tool: "flowcheck", verdict: str(raw.verdict, "UNKNOWN"), counts: countsOf(raw), findings, warnings };
}

/** Classify a depguard base value: a directory path, a git ref, or none. */
function depguardBaseKind(base: unknown): "path" | "ref" | "none" {
  if (typeof base !== "string" || base.length === 0) return "none";
  return base.startsWith("/") || base.startsWith(".") || base.startsWith("~") ? "path" : "ref";
}

export function adaptDepguard(report: unknown, root: string): AdaptedReport {
  const raw = asObj(report) ?? {};
  const findings: NormalizedFinding[] = [];
  const warnings: string[] = (Array.isArray(raw.warnings) ? raw.warnings : []).map((w) => `depguard: ${String(w)}`);
  // The diff context every depguard finding is meaningless without: what
  // the head (raw.path) was compared against, and in which mode.
  const base = typeof raw.base === "string" ? raw.base : null;
  const baseKind = depguardBaseKind(raw.base);
  const head = str(raw.path);
  const mode = str(raw.mode);
  const context: Record<string, unknown> = { base, baseKind, head, mode };
  const manifest = "package.json";

  const pushFinding = (f: Raw, dep: string, change: string, changeFields: Record<string, unknown>) => {
    const rule = str(f.rule, "unknown-rule");
    const evidence = str(f.evidence);
    const location = dep ? `${manifest}|${dep}` : manifest;
    const signature = signatureOf([
      rule,
      change,
      String(changeFields.rangeFrom ?? ""),
      String(changeFields.rangeTo ?? ""),
      String(changeFields.versionFrom ?? ""),
      String(changeFields.versionTo ?? ""),
      collapseWs(evidence),
    ]);
    findings.push({
      findingId: makeFindingId("depguard", rule, location, signature),
      identity: makeIdentity("depguard", location, rule),
      tool: "depguard",
      rule,
      severity: FACTORY_SEVERITY[str(f.severity)] ?? "low",
      file: normalizePath(manifest, effectiveRoot(report, root)),
      detail: evidence,
      excerpt: evidence ? evidence.slice(0, 200) : undefined,
      signature,
      data: {
        dependency: dep,
        change,
        ...changeFields,
        source: str(f.source),
        evidence,
        base,
        baseKind,
        head,
        mode,
        manifest,
      },
    });
  };

  const changes = Array.isArray(raw.changes) ? raw.changes : [];
  for (const entry of changes) {
    const c = asObj(entry);
    if (!c || typeof c.name !== "string" || c.name.length === 0) {
      warnings.push("depguard: skipped a malformed change entry");
      continue;
    }
    const changeFields: Record<string, unknown> = {
      rangeFrom: str(c.rangeFrom),
      rangeTo: str(c.rangeTo),
      versionFrom: str(c.versionFrom),
      versionTo: str(c.versionTo),
      changeVerdict: str(c.verdict),
    };
    // A change with no findings of its own (a clean bump) produces no
    // observation: tracewatch tracks findings, and the change itself
    // stays visible in the scan counts and the diff context.
    const nested = Array.isArray(c.findings) ? c.findings : [];
    for (const entry2 of nested) {
      const f = asObj(entry2);
      if (!f) {
        warnings.push("depguard: skipped a malformed finding entry");
        continue;
      }
      pushFinding(f, c.name, str(c.change), changeFields);
    }
  }
  const repoFindings = Array.isArray(raw.repoFindings) ? raw.repoFindings : [];
  for (const entry of repoFindings) {
    const f = asObj(entry);
    if (!f) {
      warnings.push("depguard: skipped a malformed repo finding entry");
      continue;
    }
    pushFinding(f, "", "repo", { repoLevel: true });
  }
  return { tool: "depguard", verdict: str(raw.verdict, "UNKNOWN"), counts: countsOf(raw), findings, warnings, context };
}

export function adaptReport(tool: ToolName, report: unknown, root: string): AdaptedReport {
  if (tool === "hookcheck") return adaptHookcheck(report, root);
  if (tool === "actionpin") return adaptActionpin(report, root);
  if (tool === "mcpvet") return adaptMcpvet(report, root);
  if (tool === "depguard") return adaptDepguard(report, root);
  if (tool === "flowcheck") return adaptFlowcheck(report, root);
  return adaptInjectcheck(report, root);
}
