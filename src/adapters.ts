/**
 * Adapters: translate each tool's published JSON report shape into
 * tracewatch's normalized finding observations.
 *
 * The shapes consumed are the tools' public contracts, verified against
 * hookcheck 0.1.14, actionpin 0.1.6, injectcheck 0.1.13:
 *
 * - hookcheck: {verdict, findings: [{id, file, source, hook, command,
 *   line?, classification, rules, evidence}], counts, warnings}
 * - actionpin: {verdict, actions: [{workflow, line, uses, action, ref,
 *   classification, ownerType, rawLine}], counts}
 * - injectcheck: {verdict, findings: [{file, line, rule, severity,
 *   excerpt, detail}], counts, warnings}
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

export function adaptReport(tool: ToolName, report: unknown, root: string): AdaptedReport {
  if (tool === "hookcheck") return adaptHookcheck(report, root);
  if (tool === "actionpin") return adaptActionpin(report, root);
  return adaptInjectcheck(report, root);
}
