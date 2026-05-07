import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

const BYPASS_MATRIX = [
  {
    path: "web_fetch wrapper",
    expectedCoverage: "covered",
    hook: "tool_result_persist + wrapper classifier",
    note: "Primary supported path.",
  },
  {
    path: "bash curl",
    expectedCoverage: "partial",
    hook: "before_tool_call shell-pattern guard",
    note: "Detects known curl/wget patterns before execution; does not inspect arbitrary stdout unless persisted as tool output.",
  },
  {
    path: "browser tool",
    expectedCoverage: "unknown",
    hook: "tool_result_persist / before_prompt_build if output is surfaced",
    note: "Depends on browser tool result shape and whether DOM content is persisted.",
  },
  {
    path: "custom MCP tool",
    expectedCoverage: "partial",
    hook: "before_tool_call / tool_result_persist",
    note: "Global hooks can inspect params and result text, but raw remote bytes are tool-specific.",
  },
  {
    path: "web search",
    expectedCoverage: "unknown",
    hook: "tool_result_persist if result reaches transcript",
    note: "No dedicated wrapper in this plugin.",
  },
  {
    path: "GitHub issue read",
    expectedCoverage: "covered when wrapper enabled",
    hook: "github_issue_read wrapper",
    note: "Disabled in this E2E harness by default to prevent live GitHub egress.",
  },
];

describe("bypass path coverage matrix", () => {
  it("generates the soft-warning matrix for ingestion paths outside web_fetch", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "silmaril-bypass-matrix-"));
    const file = path.join(dir, "bypass-coverage-matrix.md");
    await fs.writeFile(file, renderMatrix(), "utf8");
    const text = await fs.readFile(file, "utf8");

    expect(text).toContain("| bash curl |");
    expect(text).toContain("| custom MCP tool |");
    expect(text).toContain("No dedicated wrapper");
  });
});

function renderMatrix(): string {
  const rows = BYPASS_MATRIX.map(
    (row) => `| ${row.path} | ${row.expectedCoverage} | ${row.hook} | ${row.note} |`,
  );
  return [
    "# Firewall Bypass Path Coverage Matrix",
    "",
    "| Ingestion path | Current coverage | Hook / mechanism | Notes |",
    "| --- | --- | --- | --- |",
    ...rows,
    "",
  ].join("\n");
}
