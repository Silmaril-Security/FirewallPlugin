import { createHash } from "node:crypto";

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function shortHash16(value: string): string {
  return value.slice(0, 16);
}
