import { describe, expect, it } from "vitest";
import {
  compileBenchFile,
  readBenchLock,
  readBenchReplay,
  runBenchCase,
  runBenchCapabilityCase,
  type CompiledBenchCase,
} from "../harness/bench";
import { withGateway, missingModelEnv } from "./scenario-support";

const compiled = await compileBenchFile();
const locked = await readBenchLock();
const runnableCases = locked.cases.filter((testCase) => testCase.status === "runnable");
const pendingCases = locked.cases.filter((testCase) => testCase.status === "pending_capability");
const canRunExecutableCases = runnableCases.every((testCase) => !missingModelEnv(testCase.model));

describe("Silmaril Bench corpus", () => {
  it("has a deterministic compiled lock for all 20 corpus cases", () => {
    expect(compiled).toEqual(locked);
    expect(locked.caseCount).toBe(20);
    expect(locked.runnableCount).toBe(2);
    expect(locked.pendingCount).toBe(18);
    expect(locked.cases.map((testCase) => testCase.id)).toEqual([
      "M01",
      "M02",
      "M03",
      "M04",
      "M05",
      "M06",
      "M07",
      "M08",
      "M09",
      "M10",
      "B01",
      "B02",
      "B03",
      "B04",
      "B05",
      "B06",
      "B07",
      "B08",
      "B09",
      "B10",
    ]);
  });

  it.each(pendingCases)(
    "$id documents missing OpenClaw capabilities instead of pretending the case is runnable",
    (testCase: CompiledBenchCase) => {
      expect(testCase.missingCapabilities.length).toBeGreaterThan(0);
      expect(testCase.expected).toBeTruthy();
      expect(testCase.toolSurface.length).toBeGreaterThan(0);
    },
  );

  const run = canRunExecutableCases ? it : it.skip;
  run("runs or capability-gates all 20 cases against an isolated OpenClaw gateway and writes replays", async () => {
    await withGateway(
      {
        name: "bench-all-cases",
        model: runnableCases[0]?.model,
        keepHomeDirOnKill: true,
      },
      async (gateway) => {
        for (const testCase of locked.cases) {
          if (testCase.status === "runnable") {
            await runBenchCase(gateway, testCase);
          } else {
            await runBenchCapabilityCase(gateway, testCase);
          }
        }

        const replay = await readBenchReplay(gateway);
        const caseEnds = replay.filter(
          (entry): entry is { caseId: string; event: string; payload: { status: string } } =>
            !!entry &&
            typeof entry === "object" &&
            "event" in entry &&
            entry.event === "case_end" &&
            "caseId" in entry &&
            "payload" in entry,
        );
        expect(caseEnds.map((entry) => entry.caseId)).toEqual(locked.cases.map((testCase) => testCase.id));
        expect(caseEnds.filter((entry) => entry.payload.status === "passed").map((entry) => entry.caseId)).toEqual([
          "M01",
          "B02",
        ]);
        expect(
          caseEnds.filter((entry) => entry.payload.status === "pending_capability").map((entry) => entry.caseId),
        ).toEqual(pendingCases.map((testCase) => testCase.id));
      },
    );
  });
});
