export type BypassDetection =
  | {
      matched: true;
      details: Record<string, unknown>;
    }
  | {
      matched: false;
    };

export type BypassPattern = {
  toolName: string;
  label: string;
  detect(command: string): BypassDetection;
  buildRetryHint(details: Record<string, unknown>): string;
};

export type BypassMatch = {
  toolName: string;
  label: string;
  details: Record<string, unknown>;
  blockReason: string;
};
