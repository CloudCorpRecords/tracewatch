/**
 * Thin git helpers. Every function returns null (never throws) when git
 * is unavailable or the directory is not a repo, so callers can state
 * "not established" instead of crashing on a non-repo target.
 */
import { execFile } from "node:child_process";
import type { CommitInfo } from "./types.js";

export function git(args: string[], cwd: string, timeoutMs = 30000): Promise<string | null> {
  return new Promise((resolve) => {
    execFile("git", args, { cwd, timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 }, (err, stdout) => {
      resolve(err ? null : stdout);
    });
  });
}

export async function headSha(cwd: string): Promise<string | null> {
  const out = await git(["rev-parse", "HEAD"], cwd);
  const sha = out?.trim();
  return sha && /^[0-9a-f]{40}$/.test(sha) ? sha : null;
}

export async function commitTime(cwd: string, ref = "HEAD"): Promise<string | null> {
  const out = await git(["show", "-s", "--format=%cI", ref], cwd);
  return out ? out.trim() : null;
}

/** Parse "git@github.com:owner/repo.git" and https forms to owner/repo. */
export function parseGithubSlug(remoteUrl: string): string | null {
  const m =
    remoteUrl.match(/github\.com[:/]([^/]+)\/([^/]+?)(?:\.git)?$/) ??
    remoteUrl.match(/^([^/\s]+)\/([^/\s]+)$/);
  return m ? `${m[1]}/${m[2]}` : null;
}

export async function remoteSlug(cwd: string): Promise<string | null> {
  const out = await git(["remote", "get-url", "origin"], cwd);
  return out ? parseGithubSlug(out.trim()) : null;
}

const LOG_FORMAT = "%H%x1f%an%x1f%aI%x1f%s";

export function parseLogLine(line: string): CommitInfo | null {
  const parts = line.split("\x1f");
  if (parts.length < 4 || !/^[0-9a-f]{40}$/.test(parts[0])) return null;
  return { sha: parts[0], author: parts[1], date: parts[2], subject: parts.slice(3).join("\x1f") };
}

/**
 * Commits whose diff introduced (or removed) the needle in the file,
 * newest first, via the pickaxe. -S is a literal string search, so
 * needles with regex characters are safe as single arguments.
 */
export async function logPickaxe(cwd: string, needle: string, file?: string): Promise<CommitInfo[]> {
  if (!needle) return [];
  const args = ["log", `--format=${LOG_FORMAT}`, "-S", needle, "--"];
  if (file) args.push(file);
  const out = await git(args, cwd, 60000);
  if (!out) return [];
  return out.split("\n").map(parseLogLine).filter((c): c is CommitInfo => c !== null);
}

/** The commit git blame assigns to one line of a file at HEAD. */
export async function blameLine(cwd: string, file: string, line: number): Promise<CommitInfo | null> {
  const out = await git(["blame", "--porcelain", "-L", `${line},${line}`, "HEAD", "--", file], cwd);
  if (!out) return null;
  let sha = "";
  let author = "";
  let time = "";
  let subject = "";
  for (const l of out.split("\n")) {
    if (!sha && /^[0-9a-f]{40} /.test(l)) sha = l.split(" ")[0];
    else if (l.startsWith("author ")) author = l.slice("author ".length);
    else if (l.startsWith("author-time ")) {
      const secs = Number(l.slice("author-time ".length));
      if (Number.isFinite(secs)) time = new Date(secs * 1000).toISOString();
    } else if (l.startsWith("summary ")) subject = l.slice("summary ".length);
  }
  return sha ? { sha, author, date: time, subject } : null;
}
