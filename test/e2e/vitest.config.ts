import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/e2e/scenarios/**/*.e2e.test.ts"],
    setupFiles: ["test/e2e/vitest.setup.ts"],
    fileParallelism: false,
    testTimeout: 600_000,
    hookTimeout: 120_000,
    sequence: {
      concurrent: false,
      shuffle: false,
    },
    reporters: ["default"],
  },
});
