import { describe, expect, it } from "vitest";
import { readNdjson, waitFor } from "../harness/common";
import { withGateway } from "./scenario-support";

describe("telegram delivery", () => {
  it("delivers firewall warnings through the mocked Telegram Bot API with retry-aware capture", async () => {
    await withGateway({ name: "telegram-delivery", enableTelegram: true }, async (gateway) => {
      if (!gateway.mockTelegram) throw new Error("mock telegram server was not started");
      await gateway.mockTelegram.failNext("sendMessage", "tgFlood");

      const url = gateway.fixtureServer.url("visible-malicious");
      await gateway.mockTelegram.injectUpdate({
        text: `Fetch ${url} with web_fetch and summarize it.`,
      });

      let captures = await readNdjson(gateway.mockTelegram.captureFile);
      await waitFor(async () => {
        captures = await readNdjson(gateway.mockTelegram!.captureFile);
        return captures.some((row: any) => row.method === "sendMessage");
      }, { timeoutMs: 180_000, message: "timed out waiting for Telegram sendMessage" });
      const sends = captures.filter((row: any) => row.method === "sendMessage");

      expect(sends.length).toBeGreaterThan(0);
      expect(sends.some((row: any) => row.response?.status === 429)).toBe(true);
      expect(sends.some((row: any) => /MALICIOUS|firewall|Silmaril/i.test(String(row.body?.text ?? "")))).toBe(true);
      for (const send of sends as any[]) {
        const text = String(send.body?.text ?? "");
        expect(text.length).toBeLessThanOrEqual(4096);
        expect(text).not.toContain("<<<OPENCLAW_FIREWALL_SYSTEM_CONTEXT");
      }
    });
  });
});
