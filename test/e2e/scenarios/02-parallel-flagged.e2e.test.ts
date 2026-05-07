import { describe, expect, it } from "vitest";
import { readNdjson } from "../harness/common";
import { expectFirewallWarning, withGateway } from "./scenario-support";

describe("parallel flagged fetches", () => {
  it("keeps two sessions isolated when classifier responses complete out of order", async () => {
    await withGateway({ name: "parallel-flagged" }, async (gateway) => {
      await gateway.mockClassifier.match({
        toolNamePattern: "web_fetch",
        textPattern: "CANARY_VISIBLE_TP_20260503",
        response: { prediction: "MALICIOUS", score: 0.97, primary_outcome: "session_a_delayed", delayMs: 3000 },
      });
      await gateway.mockClassifier.match({
        toolNamePattern: "web_fetch",
        textPattern: "CANARY_HIDDEN_PROMPT_INJECTION_20260503",
        response: { prediction: "MALICIOUS", score: 0.97, primary_outcome: "session_b_fast", delayMs: 0 },
      });

      const urlA = gateway.fixtureServer.url("visible-malicious", "case=a");
      const urlB = gateway.fixtureServer.url("hidden-dom-malicious", "case=b");
      const [main, alt] = await Promise.all([
        gateway.openclawAgent(`Fetch ${urlA} with web_fetch and summarize it.`, {
          agentId: "main",
          sessionId: "parallel-main",
        }),
        gateway.openclawAgent(`Fetch ${urlB} with web_fetch and summarize it.`, {
          agentId: "alt",
          sessionId: "parallel-alt",
        }),
      ]);

      expectFirewallWarning(main.rawVisibleText);
      expectFirewallWarning(alt.rawVisibleText);

      const captures = await readNdjson(gateway.mockClassifier.captureFile);
      const outcomes = captures.map((row: any) => row.summary?.outcome).filter(Boolean);
      expect(outcomes).toContain("session_a_delayed");
      expect(outcomes).toContain("session_b_fast");
    });
  });
});
