export function isRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function isMaliciousPrediction(prediction: unknown): boolean {
  return typeof prediction === "string" && prediction.toUpperCase() === "MALICIOUS";
}
