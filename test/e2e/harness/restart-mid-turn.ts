import { spawn } from "node:child_process";
import { waitForNdjsonLines } from "./common";
import type { IsolatedGateway } from "./spawn-isolated-gateway";

export async function waitForFirewallHookThenKill(options: {
  gateway: IsolatedGateway;
  minClassifierCaptures?: number;
  timeoutMs?: number;
}): Promise<void> {
  await waitForNdjsonLines(
    options.gateway.mockClassifier.captureFile,
    options.minClassifierCaptures ?? 1,
    { timeoutMs: options.timeoutMs ?? 30_000 },
  );
  await forceKillProcess(options.gateway.child.pid);
}

export async function forceKillProcess(pid: number | undefined): Promise<void> {
  if (!pid) return;
  if (process.platform === "win32") {
    await new Promise<void>((resolve) => {
      const child = spawn("taskkill", ["/F", "/PID", String(pid)], {
        stdio: "ignore",
        windowsHide: true,
      });
      child.once("exit", () => resolve());
      child.once("error", () => resolve());
    });
    return;
  }
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // The process may already have exited.
  }
}
