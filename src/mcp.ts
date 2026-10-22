/**
 * tracewatch MCP server. Tools: ingest_scan, diff_scans,
 * finding_provenance, repo_health, watch_status, list_findings,
 * explain_finding. The store is TRACEWATCH_STORE or ~/.tracewatch.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  VERSION,
  Store,
  defaultStoreDir,
  diffScans,
  explainFinding,
  ingestPath,
  repoHealth,
} from "./core.js";

const store = new Store(defaultStoreDir());
const server = new McpServer({ name: "tracewatch", version: VERSION });

function text(value: unknown): { content: { type: "text"; text: string }[] } {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

server.tool(
  "ingest_scan",
  "Run hookcheck, actionpin, and injectcheck against a local repo path and store the results as a timestamped scan record with stable finding IDs. Returns the scan record and every finding observation. Use this to start or refresh tracking for a repo.",
  {
    path: z.string().describe("Local path of the repo or directory to scan"),
    name: z.string().optional().describe("Repo key to file the scan under (default: GitHub slug from the git remote, else the directory name)"),
    tools: z.array(z.enum(["hookcheck", "actionpin", "injectcheck"])).optional().describe("Subset of tools to run (default: all three)"),
  },
  async ({ path, name, tools }) => {
    const result = await ingestPath(store, path, { name, tools });
    return text({ scan: result.record, findings: result.observations });
  },
);

server.tool(
  "diff_scans",
  "Diff two scans of a repo (default: the last two). Reports NEW, RESOLVED, and CHANGED findings, verdict moves, and action ref events with both refs spelled out, including pin regressions (PINNED to MUTABLE or BRANCH) and bare ref moves on pinned actions.",
  {
    repo: z.string().describe("Repo key used at ingest"),
    from: z.string().optional().describe("Earlier scanId (default: the scan before `to`)"),
    to: z.string().optional().describe("Later scanId (default: the latest scan)"),
  },
  async ({ repo, from, to }) => text(diffScans(store, repo, from, to)),
);

server.tool(
  "finding_provenance",
  "Root-cause provenance for one finding: the introducing commit from git pickaxe on the finding's content, the current-line commit from git blame, the associated GitHub PR when the API answers, and the finding's ref history from the scan store. Confirmed evidence, inferences, and unestablished items are reported separately; nothing is guessed.",
  {
    repo: z.string().describe("Repo key used at ingest"),
    findingId: z.string().describe("Full findingId (tw_...) or a prefix of at least 8 characters"),
    path: z.string().optional().describe("Local clone path to run git evidence against (default: the path recorded at ingest)"),
  },
  async ({ repo, findingId, path }) => {
    const explained = await explainFinding(store, repo, findingId, { path });
    if (!explained) return text({ error: `finding "${findingId}" not found on repo "${repo}"` });
    return text(explained.provenance);
  },
);

server.tool(
  "repo_health",
  "Health report for a repo across all its scans: verdict trend, open findings by tool and severity, resolved count, mean time open for resolved findings, all action ref events, and watch detection latency stats (count, median, max time-to-detect).",
  { repo: z.string().describe("Repo key used at ingest") },
  async ({ repo }) => text(repoHealth(store, repo)),
);

server.tool(
  "watch_status",
  "Summarize the tracewatch store: every tracked repo with its scan count, last scan time, open finding count, detection count, and median time-to-detect. Use this to see what is being watched and tracked before drilling into one repo.",
  {},
  async () => {
    const repos = store.repos().map((repo) => {
      const health = repoHealth(store, repo);
      return {
        repo,
        scans: health.scanCount,
        lastScanAt: health.lastScanAt,
        openFindings: health.open.total,
        detections: health.detections.count,
        medianTimeToDetectMs: health.detections.medianMs,
      };
    });
    return text({ storeDir: store.dir, repos });
  },
);

server.tool(
  "list_findings",
  "List tracked findings for a repo with derived status. Filter by tool, severity, and status (open, resolved, or all; default open). Each entry carries the stable findingId usable with finding_provenance and explain_finding.",
  {
    repo: z.string().describe("Repo key used at ingest"),
    tool: z.enum(["hookcheck", "actionpin", "injectcheck"]).optional(),
    severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
    status: z.enum(["open", "resolved", "all"]).optional(),
  },
  async ({ repo, tool, severity, status }) => {
    const tracked = store
      .trackedFindings(repo)
      .filter((t) => (tool ? t.latest.tool === tool : true))
      .filter((t) => (severity ? t.latest.severity === severity : true))
      .filter((t) => (status && status !== "all" ? t.status === status : status === "all" ? true : t.status === "open"));
    return text(tracked);
  },
);

server.tool(
  "explain_finding",
  "The full evidence bundle for one finding, written to act on: the tracked finding (status, first and last seen, content versions), its scan history is summarized in the provenance record, and the provenance itself (introducing commit, PR, ref history, confirmed versus inferred versus not established).",
  {
    repo: z.string().describe("Repo key used at ingest"),
    findingId: z.string().describe("Full findingId (tw_...) or a prefix of at least 8 characters"),
    path: z.string().optional().describe("Local clone path for git evidence (default: the path recorded at ingest)"),
  },
  async ({ repo, findingId, path }) => {
    const explained = await explainFinding(store, repo, findingId, { path });
    if (!explained) return text({ error: `finding "${findingId}" not found on repo "${repo}"` });
    return text(explained);
  },
);

async function main(): Promise<void> {
  await server.connect(new StdioServerTransport());
}

void main();
