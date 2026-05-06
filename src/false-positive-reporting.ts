export const FALSE_POSITIVE_TOOL_NAME = "firewall_report_false_positive" as const;

export const DEFAULT_FALSE_POSITIVE_REPORT_URL =
  "https://j8sqlvv9pi.execute-api.us-west-2.amazonaws.com/prod/webhook" as const;

type Logger = {
  info?: (message: string) => void;
  warn?: (message: string) => void;
  error?: (message: string) => void;
};

type FalsePositiveEvidence = {
  rule_id: string;
  timestamp: string;
  blocked_action: string;
  expected_task: string;
  repeatability: string;
  blocked_url_hash: string;
  sanitized_context: string;
};

export type FalsePositiveReportPayload = {
  event_id: string;
  source: "openclaw";
  label: "suspected_false_positive";
  reason: string;
  evidence: FalsePositiveEvidence;
  confidence: number;
};

type ValidationResult =
  | {
      ok: true;
      payload: FalsePositiveReportPayload;
    }
  | {
      ok: false;
      errors: string[];
    };

type ToolResultDetails = {
  submitted: boolean;
  status?: "submitted" | "duplicate" | "failed" | "blocked";
  endpointHost?: string;
  httpStatus?: number;
  validationErrors?: string[];
};

const FIELD_LIMITS = {
  event_id: 256,
  reason: 1000,
  rule_id: 128,
  timestamp: 128,
  blocked_action: 512,
  expected_task: 512,
  repeatability: 512,
  blocked_url_hash: 256,
  sanitized_context: 2000,
} as const;

const EVIDENCE_FIELDS = [
  "rule_id",
  "timestamp",
  "blocked_action",
  "expected_task",
  "repeatability",
  "blocked_url_hash",
  "sanitized_context",
] as const;

const SECRET_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /\bhttps?:\/\/\S+/i, reason: "raw URL" },
  { pattern: /\bwww\.[^\s]+/i, reason: "raw URL" },
  { pattern: /\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\/\S+/i, reason: "URL path" },
  {
    pattern: /\b(access[_-]?token|auth[_-]?token|api[_-]?key|password|passwd|pwd|secret|session[_-]?id|credential|cookie)\s*[:=]\s*\S+/i,
    reason: "secret or credential marker",
  },
  { pattern: /\bauthorization\s*:\s*\S+/i, reason: "authorization header" },
  { pattern: /\bbearer\s+[A-Za-z0-9._~+/=-]{8,}/i, reason: "bearer token" },
  { pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/i, reason: "private key" },
  { pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i, reason: "email address" },
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/, reason: "SSN-like value" },
  { pattern: /\b(?:\d[ -]*?){13,19}\b/, reason: "payment-card-like value" },
];

export function createFalsePositiveReportTool(options: {
  reportUrl?: string;
  apiKey?: string;
  identifier?: string;
  logger?: Logger;
  fetchImpl?: typeof fetch;
}) {
  return {
    name: FALSE_POSITIVE_TOOL_NAME,
    label: "Report Firewall False Positive",
    description:
      "Submit a sanitized candidate report for a suspected firewall false positive. Use only when the firewall blocked an expected low-impact action, evidence is complete, and the report is not a ground-truth label.",
    parameters: {
      type: "object",
      additionalProperties: false,
      properties: {
        event_id: {
          type: "string",
          description: "Firewall alert, test run, or event identifier. Do not include customer data or secrets.",
        },
        reason: {
          type: "string",
          description:
            "Short sanitized reason this is suspected to be a false positive, not a ground-truth label.",
        },
        source: {
          type: "string",
          enum: ["openclaw"],
          description: 'Optional fixed source. If supplied, it must be "openclaw".',
        },
        label: {
          type: "string",
          enum: ["suspected_false_positive"],
          description:
            'Optional fixed candidate label. If supplied, it must be "suspected_false_positive".',
        },
        confidence: {
          type: "number",
          minimum: 0,
          maximum: 1,
          description: "Candidate confidence from 0 to 1.",
        },
        evidence: {
          type: "object",
          additionalProperties: false,
          properties: {
            rule_id: {
              type: "string",
              description: "Firewall rule or detector id that blocked the action.",
            },
            timestamp: {
              type: "string",
              description: "Timestamp of the blocked event, preferably ISO 8601.",
            },
            blocked_action: {
              type: "string",
              description: "Short sanitized description of the action that was blocked.",
            },
            expected_task: {
              type: "string",
              description: "Short sanitized description of the user's task that made the action expected.",
            },
            repeatability: {
              type: "string",
              description: "Sanitized evidence that the same block is repeatable.",
            },
            blocked_url_hash: {
              type: "string",
              description: "Hash of the blocked URL or network target. Do not include the raw URL.",
            },
            sanitized_context: {
              type: "string",
              description: "Minimal sanitized context. No private content, credentials, customer data, or raw URLs.",
            },
          },
          required: [...EVIDENCE_FIELDS],
        },
      },
      required: ["event_id", "reason", "confidence", "evidence"],
    },
    async execute(_id: string, params: Record<string, unknown>) {
      const validation = validateAndBuildFalsePositiveReport(params);
      if (!validation.ok) {
        return textResult(
          `False-positive candidate was not submitted: ${validation.errors.join("; ")}`,
          {
            submitted: false,
            status: "blocked",
            validationErrors: validation.errors,
          },
        );
      }

      const endpoint = resolveReportEndpoint(options.reportUrl);
      if (!endpoint.ok) {
        return textResult(
          `False-positive candidate was not submitted: ${endpoint.error}`,
          {
            submitted: false,
            status: "failed",
            validationErrors: [endpoint.error],
          },
        );
      }

      const outboundBody = buildOutboundReportBody({
        payload: validation.payload,
        endpoint: endpoint.url,
        identifier: options.identifier,
      });
      const headers: Record<string, string> = {
        "content-type": "application/json",
      };
      if (options.apiKey) {
        headers["x-api-key"] = options.apiKey;
      }

      try {
        const fetchImpl = options.fetchImpl ?? fetch;
        const response = await fetchImpl(endpoint.url.toString(), {
          method: "POST",
          headers,
          body: JSON.stringify(outboundBody),
          redirect: "error",
        });
        const responseBody = await readJsonResponse(response);

        if (isRecord(responseBody) && responseBody.error === "duplicate_report") {
          options.logger?.info?.(
            `firewall-plugin: false-positive candidate already exists at ${endpoint.url.host}`,
          );
          return textResult("False-positive candidate was already present in the review queue.", {
            submitted: true,
            status: "duplicate",
            endpointHost: endpoint.url.host,
            httpStatus: response.status,
          });
        }

        if (!response.ok) {
          return textResult(
            `False-positive candidate submission failed with HTTP ${response.status}.`,
            {
              submitted: false,
              status: "failed",
              endpointHost: endpoint.url.host,
              httpStatus: response.status,
            },
          );
        }

        options.logger?.info?.(
          `firewall-plugin: submitted suspected false-positive candidate to ${endpoint.url.host}`,
        );
        return textResult("Submitted suspected firewall false-positive candidate for review.", {
          submitted: true,
          status: "submitted",
          endpointHost: endpoint.url.host,
          httpStatus: response.status,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        options.logger?.warn?.(`firewall-plugin: false-positive report submission failed: ${message}`);
        return textResult(`False-positive candidate submission failed: ${message}`, {
          submitted: false,
          status: "failed",
          endpointHost: endpoint.url.host,
        });
      }
    },
  };
}

function buildOutboundReportBody(params: {
  payload: FalsePositiveReportPayload;
  endpoint: URL;
  identifier?: string;
}): unknown {
  if (!isFalsePositiveReviewQueueEndpoint(params.endpoint)) {
    return params.payload;
  }

  return {
    identifier: params.identifier ?? "unknown",
    timestamp: params.payload.evidence.timestamp,
    hook: normalizeHookName(params.payload.evidence.rule_id),
    payload: JSON.stringify(params.payload),
    metadata: {
      submitted_via: FALSE_POSITIVE_TOOL_NAME,
      event_id: params.payload.event_id,
      source: params.payload.source,
      label: params.payload.label,
      reason: params.payload.reason,
      evidence: params.payload.evidence,
      confidence: params.payload.confidence,
    },
  };
}

function isFalsePositiveReviewQueueEndpoint(url: URL): boolean {
  return /\/openclaw\/firewall-export\/false-positive\/?$/.test(url.pathname);
}

function normalizeHookName(ruleId: string): string {
  const normalized = ruleId.toLowerCase();
  if (normalized.includes("tool_response") || normalized.includes("tool response")) {
    return "TOOL_RESPONSE";
  }
  if (normalized.includes("tool_call") || normalized.includes("tool call")) {
    return "TOOL_CALL";
  }
  if (normalized.includes("user_input") || normalized.includes("user input")) {
    return "USER_INPUT";
  }
  return "USER_INPUT";
}

export function validateAndBuildFalsePositiveReport(rawParams: unknown): ValidationResult {
  const errors: string[] = [];
  if (!isRecord(rawParams)) {
    return { ok: false, errors: ["tool parameters must be an object"] };
  }

  const eventId = readRequiredString(rawParams, "event_id", FIELD_LIMITS.event_id, errors);
  const reason = readRequiredString(rawParams, "reason", FIELD_LIMITS.reason, errors);
  const confidence = readConfidence(rawParams.confidence, errors);
  const evidenceRaw = rawParams.evidence;

  if (!isRecord(evidenceRaw)) {
    errors.push("evidence must be an object");
  }

  const evidence = isRecord(evidenceRaw)
    ? {
        rule_id: readRequiredString(evidenceRaw, "rule_id", FIELD_LIMITS.rule_id, errors),
        timestamp: readRequiredString(evidenceRaw, "timestamp", FIELD_LIMITS.timestamp, errors),
        blocked_action: readRequiredString(
          evidenceRaw,
          "blocked_action",
          FIELD_LIMITS.blocked_action,
          errors,
        ),
        expected_task: readRequiredString(evidenceRaw, "expected_task", FIELD_LIMITS.expected_task, errors),
        repeatability: readRequiredString(evidenceRaw, "repeatability", FIELD_LIMITS.repeatability, errors),
        blocked_url_hash: readRequiredString(
          evidenceRaw,
          "blocked_url_hash",
          FIELD_LIMITS.blocked_url_hash,
          errors,
        ),
        sanitized_context: readRequiredString(
          evidenceRaw,
          "sanitized_context",
          FIELD_LIMITS.sanitized_context,
          errors,
        ),
      }
    : {
        rule_id: "",
        timestamp: "",
        blocked_action: "",
        expected_task: "",
        repeatability: "",
        blocked_url_hash: "",
        sanitized_context: "",
      };

  rejectUnsupportedFixedFields(rawParams, errors);
  validateNoUnsafeContent("event_id", eventId, errors);
  validateNoUnsafeContent("reason", reason, errors);
  validateNoUnsafeContent("evidence.rule_id", evidence.rule_id, errors);
  validateNoUnsafeContent("evidence.timestamp", evidence.timestamp, errors);
  validateNoUnsafeContent("evidence.blocked_action", evidence.blocked_action, errors);
  validateNoUnsafeContent("evidence.expected_task", evidence.expected_task, errors);
  validateNoUnsafeContent("evidence.repeatability", evidence.repeatability, errors);
  validateContentHash("evidence.blocked_url_hash", evidence.blocked_url_hash, errors);
  validateNoUnsafeContent("evidence.sanitized_context", evidence.sanitized_context, errors);

  if (errors.length > 0) {
    return { ok: false, errors: unique(errors) };
  }

  return {
    ok: true,
    payload: {
      event_id: eventId,
      source: "openclaw",
      label: "suspected_false_positive",
      reason,
      evidence,
      confidence,
    },
  };
}

export function resolveFalsePositiveReportUrl(configValue: unknown): string | undefined {
  if (typeof configValue === "string" && configValue.trim().length > 0) {
    return configValue.trim();
  }

  if (process.env.FIREWALL_REPORT_LIVE_WEBHOOK === "1") {
    const override = process.env.FIREWALL_REPORT_URL?.trim();
    return override && override.length > 0 ? override : DEFAULT_FALSE_POSITIVE_REPORT_URL;
  }

  return undefined;
}

function resolveReportEndpoint(reportUrl: string | undefined):
  | { ok: true; url: URL }
  | { ok: false; error: string } {
  if (!reportUrl) {
    return {
      ok: false,
      error:
        "falsePositiveReportUrl is not configured. Set it to a review-queue endpoint or run the live canary with FIREWALL_REPORT_LIVE_WEBHOOK=1.",
    };
  }

  try {
    const url = new URL(reportUrl);
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      return { ok: false, error: "falsePositiveReportUrl must use http or https" };
    }
    return { ok: true, url };
  } catch {
    return { ok: false, error: "falsePositiveReportUrl is not a valid URL" };
  }
}

function readRequiredString(
  record: Record<string, unknown>,
  key: string,
  maxLength: number,
  errors: string[],
): string {
  const value = record[key];
  if (typeof value !== "string") {
    errors.push(`${key} is required`);
    return "";
  }

  const trimmed = value.trim();
  if (!trimmed) {
    errors.push(`${key} must not be empty`);
    return "";
  }

  if (trimmed.length > maxLength) {
    errors.push(`${key} exceeds ${maxLength} characters`);
  }

  return trimmed;
}

function readConfidence(value: unknown, errors: string[]): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    errors.push("confidence must be a number from 0 to 1");
    return 0;
  }

  if (value < 0 || value > 1) {
    errors.push("confidence must be between 0 and 1");
  }

  return value;
}

function rejectUnsupportedFixedFields(rawParams: Record<string, unknown>, errors: string[]): void {
  if ("source" in rawParams && rawParams.source !== "openclaw") {
    errors.push('source is fixed by the tool and must not be supplied as anything other than "openclaw"');
  }

  if ("label" in rawParams && rawParams.label !== "suspected_false_positive") {
    errors.push(
      'label is fixed by the tool and must not be supplied as anything other than "suspected_false_positive"',
    );
  }
}

function validateNoUnsafeContent(path: string, value: string, errors: string[]): void {
  if (!value) return;

  for (const { pattern, reason } of SECRET_PATTERNS) {
    if (pattern.test(value)) {
      errors.push(`${path} appears to contain ${reason}`);
    }
  }
}

function validateContentHash(path: string, value: string, errors: string[]): void {
  for (const { pattern, reason } of SECRET_PATTERNS) {
    if (reason === "email address" || reason === "SSN-like value" || reason === "payment-card-like value") {
      continue;
    }
    if (pattern.test(value)) {
      errors.push(`${path} appears to contain ${reason}`);
    }
  }

  if (!value) return;

  const normalized = value.startsWith("sha256:") ? value.slice("sha256:".length) : value;
  if (!/^[A-Fa-f0-9]{32,128}$/.test(normalized)) {
    errors.push(`${path} must be a hash value, not raw content or a raw URL`);
  }
}

function textResult(text: string, details: ToolResultDetails) {
  return {
    content: [
      {
        type: "text",
        text,
      },
    ],
    details,
  };
}

async function readJsonResponse(response: Response): Promise<unknown> {
  const text = await response.text().catch(() => "");
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}
