import { describe, expect, it } from "vitest";
import { readNdjson, waitFor, waitForNdjsonLines } from "../harness/common";
import type { FakeS3Failure } from "../harness/fake-s3";
import { withGateway } from "./scenario-support";

type S3LogRow = {
  ts: string;
  method: string;
  key: string;
  contentLength: number;
  failure?: FakeS3Failure;
  jsonlLineCount?: number;
};

type RetryCase = {
  failure: FakeS3Failure;
  notes: string;
};

const RETRY_CASES: RetryCase[] = [
  { failure: "s3ExpiredToken", notes: "lease refresh + retry" },
  { failure: "s3KeyAlreadyExists", notes: "retry with new object key" },
  { failure: "s3RequestTimeout", notes: "release to pending; retry next tick" },
  { failure: "s3InvalidAccessKey", notes: "documents current behavior" },
  { failure: "s3SignatureMismatch", notes: "same family as InvalidAccessKey" },
  { failure: "s3WAFBlock", notes: "403 HTML; eventual retry success" },
  { failure: "s3ConnectionReset", notes: "fetch fails; retry next tick" },
];

describe("s3 failure matrix (mock-based)", () => {
  it.each(RETRY_CASES)(
    "exporter retries and succeeds after $failure ($notes)",
    async ({ failure }) => {
      await withGateway({ name: `s3-${failure}` }, async (gateway) => {
        await gateway.fakeS3.failNext(failure);
        // One agent turn produces multiple hook events that the exporter
        // batches and uploads. The first upload hits the queued failure;
        // the next 60s tick retries.
        await gateway.openclawAgent("Reply: ok", { sessionId: `s3-${failure}` });

        // Wait for at least 2 upload attempts (failure + success).
        const rows = (await waitForNdjsonLines(gateway.fakeS3.requestLog, 2, {
          timeoutMs: 180_000,
        })) as S3LogRow[];

        const failedRow = rows.find((r) => r.failure === failure);
        const successRow = rows.find((r) => !r.failure);
        expect(failedRow, `expected one row with failure=${failure}`).toBeDefined();
        expect(successRow, "expected at least one successful upload after retry").toBeDefined();
        // Note: per-attempt S3 key tracking would require fake-s3 to parse the
        // `file` form-field's filename (it currently only extracts a `key` field
        // which the presigned POST doesn't include). For now we only verify
        // that both attempts were observed.
      });
    },
    240_000,
  );

  it("exporter handles s3EntityTooLarge without infinite retry", async () => {
    // EntityTooLarge is a permanent failure — the batch can't shrink itself.
    // Behavior should be either drop/quarantine or single-attempt + skip;
    // it must NOT retry forever (which would show as N>2 failure rows).
    await withGateway({ name: "s3-entity-too-large" }, async (gateway) => {
      await gateway.fakeS3.failNext("s3EntityTooLarge");
      await gateway.openclawAgent("Reply: ok", { sessionId: "s3-entity-too-large" });

      // Wait for the first failure to land.
      const initial = (await waitForNdjsonLines(gateway.fakeS3.requestLog, 1, {
        timeoutMs: 120_000,
      })) as S3LogRow[];
      expect(initial.some((r) => r.failure === "s3EntityTooLarge")).toBe(true);

      // Then wait an additional ~150s and assert: rows for THIS failure don't
      // grow without bound. Fresh successful uploads (different events from
      // ongoing hooks) are fine and expected.
      await new Promise((r) => setTimeout(r, 150_000));
      const final = (await readNdjson(gateway.fakeS3.requestLog)) as S3LogRow[];
      const entityTooLargeRows = final.filter((r) => r.failure === "s3EntityTooLarge");
      expect(
        entityTooLargeRows.length,
        `expected EntityTooLarge to NOT loop; saw ${entityTooLargeRows.length} attempts`,
      ).toBeLessThanOrEqual(3);
    });
  }, 360_000);

  it("s3ConnectionReset: connection drop is logged before destroy", async () => {
    // fake-s3 records the request (line 73-80) BEFORE destroying the socket
    // (line 82-84), so the failure row should still appear even though the
    // exporter sees a network error. Verifies the fake-s3 ordering matches
    // what we depend on across other tests.
    await withGateway({ name: "s3-connection-reset-logging" }, async (gateway) => {
      await gateway.fakeS3.failNext("s3ConnectionReset");
      await gateway.openclawAgent("Reply: ok", { sessionId: "s3-conn-reset-log" });
      await waitFor(
        async () => {
          const rows = (await readNdjson(gateway.fakeS3.requestLog)) as S3LogRow[];
          return rows.some((r) => r.failure === "s3ConnectionReset");
        },
        { timeoutMs: 120_000, intervalMs: 1000 },
      );
    });
  }, 180_000);
});
