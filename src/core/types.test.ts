import assert from "node:assert/strict";
import test from "node:test";

import type { ContentMarkerKind, SourceLabel, WrapperContext } from "./types";

test("wrapper context accepts the shared invariant shape", () => {
  const source: SourceLabel = "github_issue";
  const markerKind: ContentMarkerKind = "GITHUB";
  const ctx: WrapperContext = {
    toolName: "github_issue_read",
    source,
    markerKind,
    firewall: {
      async classify() {
        return { prediction: "BENIGN", score: 0 };
      },
    },
  };

  assert.equal(ctx.toolName, "github_issue_read");
  assert.equal(ctx.source, "github_issue");
  assert.equal(ctx.markerKind, "GITHUB");
});
