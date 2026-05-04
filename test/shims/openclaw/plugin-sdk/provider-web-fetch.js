export function jsonResult(value) {
  return {
    type: "json",
    json: value,
  };
}

export function markdownToText(value) {
  return String(value)
    .replace(/```[\s\S]*?```/g, "")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/!\[[^\]]*\]\([^)]+\)/g, "")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/[*_~>#-]/g, "")
    .trim();
}

export function readNumberParam(params, key, options = {}) {
  const value = params?.[key];
  if (value === undefined || value === null) {
    if (options.required) throw new Error(`${key} is required`);
    return undefined;
  }
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`${key} must be a number`);
  }
  if (options.integer && !Number.isInteger(value)) {
    throw new Error(`${key} must be an integer`);
  }
  return value;
}

export async function readResponseText(response, options = {}) {
  const text = await response.text();
  const maxBytes = options.maxBytes ?? Number.POSITIVE_INFINITY;
  if (!Number.isFinite(maxBytes)) return { text, truncated: false };
  const encoded = new TextEncoder().encode(text);
  if (encoded.byteLength <= maxBytes) return { text, truncated: false };
  return {
    text: new TextDecoder().decode(encoded.slice(0, maxBytes)),
    truncated: true,
  };
}

export function readStringParam(params, key, options = {}) {
  const value = params?.[key];
  if (value === undefined || value === null || value === "") {
    if (options.required) throw new Error(`${key} is required`);
    return undefined;
  }
  if (typeof value !== "string") {
    throw new Error(`${key} must be a string`);
  }
  return value;
}

export function resolveTimeoutSeconds(value, fallback) {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) return fallback;
  return Math.max(1, Math.floor(value));
}

export function truncateText(value, maxChars) {
  const text = String(value);
  if (text.length <= maxChars) {
    return { text, truncated: false };
  }
  return {
    text: text.slice(0, Math.max(0, maxChars)),
    truncated: true,
  };
}

export async function withStrictWebToolsEndpoint(request, handler) {
  const fetchImpl = request.fetchImpl ?? fetch;
  const response = await fetchImpl(request.url, {
    ...request.init,
    signal: request.signal,
  });
  return handler({
    response,
    finalUrl: response.url || request.url,
  });
}

export async function withTrustedWebToolsEndpoint(request, handler) {
  return withStrictWebToolsEndpoint(request, handler);
}

export function wrapWebContent(value, source = "web_fetch") {
  return [
    `<<<UNTRUSTED_WEB_CONTENT source="${source}">>>`,
    String(value),
    `<<<END_UNTRUSTED_WEB_CONTENT source="${source}">>>`,
  ].join("\n");
}
