import { truncateText, wrapWebContent } from "openclaw/plugin-sdk/provider-web-fetch";
import type { SourceLabel } from "./types";

export type WrappedContent = {
  text: string;
  truncated: boolean;
};

export function wrapAndTruncate(input: {
  value: string;
  source: SourceLabel | string;
  maxChars: number;
}): WrappedContent {
  const wrapped = wrapWebContent(input.value, input.source);
  return truncateText(wrapped, input.maxChars);
}
