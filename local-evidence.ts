import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  open,
  rename,
  rm,
} from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

export const LOCAL_PROTECTION_EVENT_SCHEMA_VERSION = 1;
export const MAX_LOCAL_PROTECTION_EVENT_BYTES = 64 * 1024;
const RUNTIME_CHECK_MARKER = /\bsilmaril-runtime-check:([A-Za-z0-9-]{16,128})\b/;

export type LocalHost = "openClaw" | "openCode";
export type LocalHook =
  | "user_input"
  | "pre_tool"
  | "post_tool"
  | "tool_result"
  | "llm_output"
  | "subagent"
  | "unknown";
export type LocalMode = "block" | "shadow";
export type LocalPolicyDecision = "allow" | "monitor" | "block" | "unavailable";
export type LocalNativeAction =
  | "none"
  | "allowed"
  | "block_returned"
  | "content_replaced"
  | "failed"
  | "unavailable";

type ClassificationLike = {
  prediction?: unknown;
  score?: unknown;
  threshold?: unknown;
  primaryOutcome?: unknown;
  primary_outcome?: unknown;
};

export type LocalProtectionEventInput = {
  host: LocalHost;
  hook: LocalHook;
  mode: LocalMode;
  rawText: string;
  requestIdentity?: string;
  sessionIdentity?: string;
  toolName?: string;
  classification: ClassificationLike;
  policyDecision: LocalPolicyDecision;
  nativeAction: LocalNativeAction;
  producer: string;
  producerVersion: string;
  pluginVersion: string;
  policyVersion: string;
  occurredAt?: Date;
};

export type LocalProtectionEventV1 = {
  schemaVersion: 1;
  id: string;
  occurredAt: string;
  host: LocalHost;
  hook: LocalHook;
  mode: LocalMode;
  requestFingerprint: string;
  sessionFingerprint?: string;
  toolDisplayName?: string;
  riskClass: string;
  attemptedConsequence: {
    category: string;
    summary: string;
  };
  prediction: "benign" | "malicious" | "unknown" | "unavailable";
  modelScore?: number;
  modelThreshold?: number;
  policyDecision: LocalPolicyDecision;
  nativeAction: LocalNativeAction;
  outcome: "not_observed";
  evidenceTruth: "plugin_reported" | "native_response_returned";
  evidenceCompleteness: "partial";
  provenance: {
    schemaVersion: 1;
    producer: string;
    producerVersion: string;
    pluginVersion: string;
    policyVersion: string;
    observedAt: string;
  };
};

type EmitOptions = {
  directory?: string;
  environment?: Record<string, string | undefined>;
  homeDirectory?: string;
};

const CONSEQUENCE_SUMMARIES: Record<string, string> = {
  credential_exposure: "A credential could be exposed by the proposed agent action.",
  sensitive_data_exposure: "Sensitive data could leave its intended boundary.",
  code_execution: "The proposed agent action could execute untrusted code.",
  destructive_change: "The proposed agent action could cause a destructive change.",
  external_communication: "The proposed agent action could communicate externally.",
  privilege_change: "The proposed agent action could change privileges.",
  unsafe_agent_control: "Untrusted content could redirect delegated agent authority.",
  other: "The proposed agent action could cause a consequential outcome.",
  unknown: "The attempted consequence could not be determined from bounded metadata.",
};

export function buildLocalProtectionEvent(
  input: LocalProtectionEventInput,
): LocalProtectionEventV1 {
  const occurredAt = input.occurredAt ?? new Date();
  const observedAt = occurredAt.toISOString();
  const runtimeCheck = input.rawText.match(RUNTIME_CHECK_MARKER)?.[0];
  const requestFingerprint = runtimeCheck
    ? sha256(runtimeCheck)
    : fingerprint([
      input.producer,
      input.hook,
      input.requestIdentity ?? "",
      sha256(input.rawText),
    ]);
  const sessionFingerprint = input.sessionIdentity
    ? fingerprint([input.host, input.sessionIdentity])
    : undefined;
  const category = consequenceCategory(input.classification);
  const prediction = normalizePrediction(input.classification.prediction);
  const modelScore = unitInterval(input.classification.score);
  const modelThreshold = unitInterval(input.classification.threshold);
  const id = stableContractID("protection-event", [
    input.host,
    input.hook,
    requestFingerprint,
    sessionFingerprint ?? "",
    input.mode,
    input.policyDecision,
    input.nativeAction,
    input.requestIdentity ? "" : observedAt,
  ]);

  return omitUndefined({
    schemaVersion: LOCAL_PROTECTION_EVENT_SCHEMA_VERSION,
    id,
    occurredAt: observedAt,
    host: input.host,
    hook: input.hook,
    mode: input.mode,
    requestFingerprint,
    sessionFingerprint,
    toolDisplayName: safeToolDisplayName(input.toolName),
    riskClass: category,
    attemptedConsequence: {
      category,
      summary: boundedSummary(
        CONSEQUENCE_SUMMARIES[category] ?? CONSEQUENCE_SUMMARIES.unknown,
      ),
    },
    prediction,
    modelScore,
    modelThreshold,
    policyDecision: input.policyDecision,
    nativeAction: input.nativeAction,
    outcome: "not_observed" as const,
    evidenceTruth: input.nativeAction === "block_returned"
        || input.nativeAction === "content_replaced"
      ? "native_response_returned" as const
      : "plugin_reported" as const,
    evidenceCompleteness: "partial" as const,
    provenance: {
      schemaVersion: 1 as const,
      producer: boundedIdentifier(input.producer, 128),
      producerVersion: boundedIdentifier(input.producerVersion, 128),
      pluginVersion: boundedIdentifier(input.pluginVersion, 128),
      policyVersion: boundedIdentifier(input.policyVersion, 128),
      observedAt,
    },
  }) as LocalProtectionEventV1;
}

export function emitLocalProtectionEventBestEffort(
  input: LocalProtectionEventInput,
  options: EmitOptions = {},
): void {
  void emitLocalProtectionEvent(input, options).catch(() => {
    // Evidence is explicitly best-effort and must never alter host enforcement.
  });
}

export async function emitLocalProtectionEvent(
  input: LocalProtectionEventInput,
  options: EmitOptions = {},
): Promise<string> {
  const event = buildLocalProtectionEvent(input);
  const encoded = Buffer.from(`${stableJSONStringify(event)}\n`, "utf8");
  if (encoded.byteLength > MAX_LOCAL_PROTECTION_EVENT_BYTES) {
    throw new Error("Local protection event exceeds the bounded event size.");
  }

  const directory = options.directory
    ?? resolveLocalEventDirectory(
      options.environment ?? process.env,
      options.homeDirectory ?? homedir(),
    );
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const directoryStat = await lstat(directory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
    throw new Error("Local evidence directory must be a real directory.");
  }
  await chmod(directory, 0o700);

  const eventDigest = sha256(event.id);
  const destination = path.join(directory, `event-${eventDigest}.json`);
  const temporary = path.join(
    directory,
    `.event-${eventDigest}.${randomUUID()}.tmp`,
  );

  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(encoded);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await chmod(temporary, 0o600);
    await rename(temporary, destination);
    await chmod(destination, 0o600);
    return destination;
  } catch (error) {
    await handle?.close().catch(() => {});
    await rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

export function resolveLocalEventDirectory(
  environment: Record<string, string | undefined> = process.env,
  homeDirectory = homedir(),
): string {
  const configured = environment.SILMARIL_LOCAL_EVENT_DIR?.trim();
  return configured || path.join(
    homeDirectory,
    "Library",
    "Application Support",
    "Silmaril",
    "Evidence",
    "incoming",
  );
}

function normalizePrediction(
  value: unknown,
): LocalProtectionEventV1["prediction"] {
  if (value === "MALICIOUS") return "malicious";
  if (value === "BENIGN") return "benign";
  if (value === undefined || value === null) return "unavailable";
  return "unknown";
}

function consequenceCategory(result: ClassificationLike): string {
  const raw = typeof result.primaryOutcome === "string"
    ? result.primaryOutcome
    : typeof result.primary_outcome === "string"
      ? result.primary_outcome
      : undefined;
  switch (raw?.trim().toLowerCase()) {
    case "secret_exposure":
      return "credential_exposure";
    case "information_disclosure":
      return "sensitive_data_exposure";
    case "system_compromise":
      return "code_execution";
    case "service_disruption":
      return "destructive_change";
    case "control_abuse":
    case "prompt_injection":
      return "unsafe_agent_control";
    case "benign":
    case undefined:
      return "unknown";
    default:
      return "other";
  }
}

function safeToolDisplayName(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed || trimmed.length > 64) return undefined;
  if (!/^[A-Za-z][A-Za-z0-9._-]*$/.test(trimmed)) return "redacted_tool";
  if (/(secret|token|credential|password|api[_-]?key)/i.test(trimmed)) {
    return "redacted_tool";
  }
  return trimmed;
}

function boundedSummary(value: string): string {
  return value
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 280);
}

function boundedIdentifier(value: string, maximum: number): string {
  return value
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .trim()
    .slice(0, maximum);
}

function unitInterval(value: unknown): number | undefined {
  return typeof value === "number"
    && Number.isFinite(value)
    && value >= 0
    && value <= 1
    ? value
    : undefined;
}

function fingerprint(components: string[]): string {
  return `sha256:${sha256(frame(components))}`;
}

function stableContractID(namespace: string, components: string[]): string {
  return `${namespace}:${sha256(frame([namespace, ...components]))}`;
}

function frame(components: string[]): string {
  return components
    .map((component) => `${Buffer.byteLength(component, "utf8")}:${component}`)
    .join("|");
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function stableJSONStringify(value: unknown): string {
  return JSON.stringify(sortJSON(value));
}

function sortJSON(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJSON);
  if (!value || typeof value !== "object") return value;
  const record = value as Record<string, unknown>;
  return Object.fromEntries(
    Object.keys(record)
      .sort()
      .map((key) => [key, sortJSON(record[key])]),
  );
}

function omitUndefined<T extends Record<string, unknown>>(record: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(record).filter(([, value]) => value !== undefined),
  ) as Partial<T>;
}
