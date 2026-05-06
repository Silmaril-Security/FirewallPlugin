import type { SourceLabel } from "./types";
import { shortHash16 } from "./hashing";

export function buildApprovalHandle(source: SourceLabel, contentHash: string): string {
  return `silmaril-${source.replace(/_/g, "-")}-${shortHash16(contentHash)}`;
}
