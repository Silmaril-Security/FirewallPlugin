import { describe, expect, it } from "vitest";
import { readNdjson } from "../harness/common";
import type { ForcedClassifierResponse } from "../harness/mock-classifier";
import { withGateway } from "./scenario-support";

const CLASSIFIER_FAILURES: Array<{
  name: string;
  response: ForcedClassifierResponse;
  expected: RegExp;
}> = [
  { name: "http_500", response: { force500: true }, expected: /failed|BENIGN|error|firewall/i },
  { name: "http_403", response: { force403: true }, expected: /failed|BENIGN|error|firewall/i },
  { name: "malformed_json", response: { forceMalformed: true }, expected: /failed|BENIGN|error|firewall/i },
  { name: "malformed_non_json", response: { forceMalformedNonJson: true }, expected: /failed|BENIGN|error|firewall/i },
  { name: "connection_reset", response: { forceProcessKill: true }, expected: /failed|BENIGN|error|firewall/i },
];

describe("failure matrix", () => {
  it.each(CLASSIFIER_FAILURES)(
    "handles classifier failure mode $name deterministically",
    async ({ name, response, expected }) => {
      await withGateway({ name: `failure-${name}` }, async (gateway) => {
        await gateway.mockClassifier.match({
          toolNamePattern: "web_fetch",
          textPattern: "Fixture TN-2026",
          response,
        });

        const url = gateway.fixtureServer.url("visible-benign");
        const result = await gateway.openclawAgent(`Fetch ${url} with web_fetch and summarize it.`, {
          sessionId: `failure-${name}`,
        });

        expect(result.rawVisibleText).toMatch(expected);
        const captures = await readNdjson(gateway.mockClassifier.captureFile);
        expect(captures.some((row: any) => row.summary?.toolName === "web_fetch")).toBe(true);
      });
    },
  );

  it("surfaces fake S3 SlowDown as the current no-retry exporter behavior", async () => {
    await withGateway({ name: "failure-s3-slowdown" }, async (gateway) => {
      await gateway.fakeS3.failNext("s3SlowDown");
      const url = gateway.fixtureServer.url("visible-benign");
      const result = await gateway.openclawAgent(`Fetch ${url} with web_fetch and summarize it.`, {
        sessionId: "failure-s3-slowdown",
      });

      expect(result.rawVisibleText).toMatch(/North Pier|sapphire|Bay 14|normal receiving/i);
      const requests = await readNdjson(gateway.fakeS3.requestLog);
      expect(requests.some((row: any) => row.failure === "s3SlowDown")).toBe(true);
    });
  });
});
