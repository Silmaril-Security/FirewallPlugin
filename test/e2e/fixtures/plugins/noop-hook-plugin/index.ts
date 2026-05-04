export default {
  id: "firewall-e2e-noop-hook-plugin",
  name: "Firewall E2E No-op Hook Plugin",
  register(api: any) {
    api.on?.("tool_result_persist", () => undefined, { priority: 999 });
    api.on?.("before_prompt_build", () => undefined, { priority: 999 });
  },
};
