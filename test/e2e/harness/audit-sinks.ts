import fs from "node:fs/promises";
import path from "node:path";

export type SinkMatch = {
  sink: string;
  canary: string;
  line: number;
  location: string;
};

export type CanaryAuditResult = {
  matches: SinkMatch[];
  bySink: Record<string, number>;
};

export async function auditCanarySinks(options: {
  rootDir: string;
  homeDir: string;
  canaries: readonly string[];
  extraSinks?: readonly string[];
}): Promise<CanaryAuditResult> {
  const candidates = [
    path.join(options.rootDir, "fp-review.ndjson"),
    path.join(options.rootDir, "mock-classifier-captures.ndjson"),
    path.join(options.rootDir, "telegram-out.ndjson"),
    path.join(options.rootDir, "fp-webhook-captures.ndjson"),
    path.join(options.rootDir, "fp-review-uploads.ndjson"),
    path.join(options.rootDir, "upload-lease.ndjson"),
    path.join(options.rootDir, "fake-s3-requests.ndjson"),
    path.join(options.rootDir, "gateway.stdout.log"),
    path.join(options.rootDir, "gateway.stderr.log"),
    path.join(options.homeDir, ".openclaw"),
    path.join(options.homeDir, "firewall-plugin"),
    ...(options.extraSinks ?? []),
  ];
  const files = await expandFiles(candidates);
  const matches: SinkMatch[] = [];

  for (const file of files) {
    const text = await fs.readFile(file, "utf8").catch(() => "");
    if (!text) continue;
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      for (const canary of options.canaries) {
        if (lines[i]?.includes(canary)) {
          matches.push({
            sink: sinkName(options.rootDir, options.homeDir, file),
            canary,
            line: i + 1,
            location: file,
          });
        }
      }
    }
  }

  return {
    matches,
    bySink: matches.reduce<Record<string, number>>((acc, match) => {
      acc[match.sink] = (acc[match.sink] ?? 0) + 1;
      return acc;
    }, {}),
  };
}

export function unexpectedCanaryMatches(
  audit: CanaryAuditResult,
  allow: (match: SinkMatch) => boolean,
): SinkMatch[] {
  return audit.matches.filter((match) => !allow(match));
}

async function expandFiles(candidates: readonly string[]): Promise<string[]> {
  const out: string[] = [];
  for (const candidate of candidates) {
    const stat = await fs.stat(candidate).catch(() => undefined);
    if (!stat) continue;
    if (stat.isFile()) {
      out.push(candidate);
      continue;
    }
    if (!stat.isDirectory()) continue;
    await walk(candidate, out);
  }
  return out;
}

async function walk(dir: string, out: string[]): Promise<void> {
  const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walk(full, out);
    } else if (entry.isFile() && isTextLike(full)) {
      out.push(full);
    }
  }
}

function isTextLike(file: string): boolean {
  return /\.(json|jsonl|ndjson|log|txt|md|html|xml|tmp|ready)$/i.test(file) || !path.extname(file);
}

function sinkName(rootDir: string, homeDir: string, file: string): string {
  const normalized = path.resolve(file);
  const root = path.resolve(rootDir);
  const home = path.resolve(homeDir);
  if (normalized.startsWith(root)) return path.relative(root, normalized) || ".";
  if (normalized.startsWith(home)) return path.join("<home>", path.relative(home, normalized));
  return normalized;
}
