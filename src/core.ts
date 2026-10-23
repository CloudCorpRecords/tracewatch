/**
 * tracewatch core facade. The domain logic lives in focused modules:
 * adapters (report shapes), ingest (tool runs and imports), store
 * (JSONL persistence and derived status), diff, blame (provenance),
 * report (health), and watch (early detection with time-to-detect).
 */
export const VERSION = "0.2.0";

export * from "./types.js";
export * from "./util.js";
export * from "./store.js";
export * from "./adapters.js";
export * from "./ingest.js";
export * from "./diff.js";
export * from "./blame.js";
export * from "./report.js";
export * from "./watch.js";
export * from "./render.js";
export * from "./git.js";
