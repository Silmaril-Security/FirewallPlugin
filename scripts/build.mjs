import { build } from "esbuild";
import { mkdir, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distDir = path.join(repoRoot, "dist");

await rm(distDir, { recursive: true, force: true });
await mkdir(distDir, { recursive: true });

await build({
  entryPoints: [path.join(repoRoot, "index.ts")],
  outfile: path.join(distDir, "index.js"),
  platform: "node",
  format: "esm",
  target: "node22",
  bundle: true,
  packages: "external",
});
