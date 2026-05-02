export const FALSE_NEGATIVE_TOOL_NAME = "firewall_report_false_negative" as const;

export const DEFAULT_FALSE_NEGATIVE_REPORT_URL =
  "https://j8sqlvv9pi.execute-api.us-west-2.amazonaws.com/prod/webhook" as const;

type Logger = {
  info?: (message: string) => void;
  warn?: (message: string) => void;
  error?: (message: string) => void;
};

type FalseNegativeEvidence = {
  detector_id: string;
  timestamp: string;
  hook: string;
  tool_name: string;
  observed_label: string;
  observed_score: string;
  expected_label: string;
  repeatability: string;
  content_hash: string;
  sanitized_context: string;
};

export type FalseNegativeReportPayload = {
  event_id: string;
  source: "openclaw";
  label: "suspected_false_negative";
  reason: string;
  evidence: FalseNegativeEvidence;
  confidence: number;
};

type ValidationResult =
  | {
      ok: true;
      payload: FalseNegativeReportPayload;
    }
  | {
      ok: false;
      errors: string[];
    };

type ToolResultDetails = {
  submitted: boolean;
  status?: "submitted" | "failed" | "blocked";
  endpointHost?: string;
  httpStatus?: number;
  validationErrors?: string[];
};

const FIELD_LIMITS = {
  event_id: 256,
  reason: 1000,
  detector_id: 128,
  timestamp: 128,
  hook: 128,
  tool_name: 128,
  observed_label: 128,
  observed_score: 128,
  expected_label: 128,
  repeatability: 512,
  content_hash: 256,
  sanitized_context: 2000,
} as const;

const EVIDENCE_FIELDS = [
  "detector_id",
  "timestamp",
  "hook",
  "tool_name",
  "observed_label",
  "observed_score",
  "expected_label",
  "repeatability",
  "content_hash",
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

export function createFalseNegativeReportTool(options: {
  reportUrl?: string;
  logger?: Logger;
}) {
  return {
    name: FALSE_NEGATIVE_TOOL_NAME,
    label: "Report Firewall False Negative",
    description:
      "Submit a sanitized candidate report for a suspected firewall false negative. Use only when the firewall classification appears to have missed malicious or prompt-injection content, evidence is complete, and the report is not a ground-truth label.",
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
            "Short sanitized reason this is suspected to be a false negative, not a ground-truth label.",
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
            detector_id: {
              type: "string",
              description: "Firewall detector, model, or rule id that produced the observed label.",
            },
            timestamp: {
              type: "string",
              description: "Timestamp of the observed event, preferably ISO 8601.",
            },
            hook: {
              type: "string",
              description: "OpenClaw hook where the miss was observed, such as tool_result_persist.",
            },
            tool_name: {
              type: "string",
              description: "Tool name associated with the content, or none if not tool-related.",
            },
            observed_label: {
              type: "string",
              description: "Classifier label that was observed, such as BENIGN.",
            },
            observed_score: {
              type: "string",
              description: "Classifier score as a short string.",
            },
            expected_label: {
              type: "string",
              description: "Sanitized expected class, such as prompt_injection.",
            },
            repeatability: {
              type: "string",
              description: "Sanitized evidence that the same miss is repeatable.",
            },
            content_hash: {
              type: "string",
              description: "Hash of the fetched page, tool result, or content sample. Do not include the raw URL.",
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
      const validation = validateAndBuildFalseNegativeReport(params);
      if (!validation.ok) {
        return textResult(
          `False-negative candidate was not submitted: ${validation.errors.join("; ")}`,
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
          `False-negative candidate was not submitted: ${endpoint.error}`,
          {
            submitted: false,
            status: "failed",
            validationErrors: [endpoint.error],
          },
        );
      }

      try {
        const response = await fetch(endpoint.url.toString(), {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(validation.payload),
          redirect: "error",
        });

        if (!response.ok) {
          return textResult(
            `False-negative candidate submission failed with HTTP ${response.status}.`,
            {
              submitted: false,
              status: "failed",
              endpointHost: endpoint.url.host,
              httpStatus: response.status,
            },
          );
        }

        options.logger?.info?.(
          `firewall-plugin: submitted suspected false-negative candidate to ${endpoint.url.host}`,
        );
        return textResult("Submitted suspected firewall false-negative candidate for review.", {
          submitted: true,
          status: "submitted",
          endpointHost: endpoint.url.host,
          httpStatus: response.status,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        options.logger?.warn?.(`firewall-plugin: false-negative report submission failed: ${message}`);
        return textResult(`False-negative candidate submission failed: ${message}`, {
          submitted: false,
          status: "failed",
          endpointHost: endpoint.url.host,
        });
      }
    },
  };
}

export function validateAndBuildFalseNegativeReport(rawParams: unknown): ValidationResult {
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
        detector_id: readRequiredString(evidenceRaw, "detector_id", FIELD_LIMITS.detector_id, errors),
        timestamp: readRequiredString(evidenceRaw, "timestamp", FIELD_LIMITS.timestamp, errors),
        hook: readRequiredString(evidenceRaw, "hook", FIELD_LIMITS.hook, errors),
        tool_name: readRequiredString(evidenceRaw, "tool_name", FIELD_LIMITS.tool_name, errors),
        observed_label: readRequiredString(evidenceRaw, "observed_label", FIELD_LIMITS.observed_label, errors),
        observed_score: readRequiredString(evidenceRaw, "observed_score", FIELD_LIMITS.observed_score, errors),
        expected_label: readRequiredString(evidenceRaw, "expected_label", FIELD_LIMITS.expected_label, errors),
        repeatability: readRequiredString(evidenceRaw, "repeatability", FIELD_LIMITS.repeatability, errors),
        content_hash: readRequiredString(evidenceRaw, "content_hash", FIELD_LIMITS.content_hash, errors),
        sanitized_context: readRequiredString(
          evidenceRaw,
          "sanitized_context",
          FIELD_LIMITS.sanitized_context,
          errors,
        ),
      }
    : {
        detector_id: "",
        timestamp: "",
        hook: "",
        tool_name: "",
        observed_label: "",
        observed_score: "",
        expected_label: "",
        repeatability: "",
        content_hash: "",
        sanitized_context: "",
      };

  rejectUnsupportedFixedFields(rawParams, errors);
  validateNoUnsafeContent("event_id", eventId, errors);
  validateNoUnsafeContent("reason", reason, errors);
  validateNoUnsafeContent("evidence.detector_id", evidence.detector_id, errors);
  validateNoUnsafeContent("evidence.timestamp", evidence.timestamp, errors);
  validateNoUnsafeContent("evidence.hook", evidence.hook, errors);
  validateNoUnsafeContent("evidence.tool_name", evidence.tool_name, errors);
  validateNoUnsafeContent("evidence.observed_label", evidence.observed_label, errors);
  validateNoUnsafeContent("evidence.observed_score", evidence.observed_score, errors);
  validateNoUnsafeContent("evidence.expected_label", evidence.expected_label, errors);
  validateNoUnsafeContent("evidence.repeatability", evidence.repeatability, errors);
  validateContentHash(evidence.content_hash, errors);
  validateNoUnsafeContent("evidence.sanitized_context", evidence.sanitized_context, errors);

  if (errors.length > 0) {
    return { ok: false, errors: unique(errors) };
  }

  return {
    ok: true,
    payload: {
      event_id: eventId,
      source: "openclaw",
      label: "suspected_false_negative",
      reason,
      evidence,
      confidence,
    },
  };
}

export function resolveFalseNegativeReportUrl(configValue: unknown): string | undefined {
  if (typeof configValue === "string" && configValue.trim().length > 0) {
    return configValue.trim();
  }

  if (process.env.FIREWALL_REPORT_LIVE_WEBHOOK === "1") {
    const override = process.env.FIREWALL_REPORT_URL?.trim();
    return override && override.length > 0 ? override : DEFAULT_FALSE_NEGATIVE_REPORT_URL;
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

  if ("label" in rawParams && rawParams.label !== "suspected_false_negative") {
    errors.push(
      'label is fixed by the tool and must not be supplied as anything other than "suspected_false_negative"',
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

function validateContentHash(value: string, errors: string[]): void {
  for (const { pattern, reason } of SECRET_PATTERNS) {
    if (reason === "email address" || reason === "SSN-like value" || reason === "payment-card-like value") {
      continue;
    }
    if (pattern.test(value)) {
      errors.push(`evidence.content_hash appears to contain ${reason}`);
    }
  }

  if (!value) return;

  const normalized = value.startsWith("sha256:") ? value.slice("sha256:".length) : value;
  if (!/^[A-Fa-f0-9]{32,128}$/.test(normalized)) {
    errors.push("evidence.content_hash must be a hash value, not raw content or a raw URL");
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}
