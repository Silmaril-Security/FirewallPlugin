import fs from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { expectFirewallWarning, withGateway } from "./scenario-support";

describe("approval handle collision", () => {
  it("does not mis-attribute parallel approvals when identical content is fetched from different URLs", async () => {
    await withGateway({ name: "handle-collision" }, async (gateway) => {
      const urlA = gateway.fixtureServer.url("false-positive", "copy=a");
      const urlB = gateway.fixtureServer.url("false-positive", "copy=b");
      const [a, b] = await Promise.all([
        gateway.openclawAgent(`Fetch ${urlA} with web_fetch and summarize it.`, {
          agentId: "main",
          sessionId: "collision-main",
        }),
        gateway.openclawAgent(`Fetch ${urlB} with web_fetch and summarize it.`, {
          agentId: "alt",
          sessionId: "collision-alt",
        }),
      ]);

      expectFirewallWarning(a.rawVisibleText);
      expectFirewallWarning(b.rawVisibleText);

      const transcript = await readAllText(path.join(gateway.homeDir, ".openclaw", "agents"));
      const handles = [...transcript.matchAll(/silmaril-web-fetch-[a-f0-9]{16}/g)].map((match) => match[0]);
      expect(new Set(handles).size).toBe(1);
      expect(handles.length).toBeGreaterThanOrEqual(2);
    });
  });
});

async function readAllText(dir: string): Promise<string> {
  const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
  const parts: string[] = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      parts.push(await readAllText(full));
    } else if (entry.isFile() && /\.(jsonl|json)$/i.test(entry.name)) {
      parts.push(await fs.readFile(full, "utf8").catch(() => ""));
    }
  }
  return parts.join("\n");
}
