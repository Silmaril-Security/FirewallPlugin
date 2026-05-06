export async function assertNoExternalFetch(): Promise<void> {
  try {
    await fetch("https://example.com");
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/net connect|not allowed|MockAgent|fetch failed/i.test(message)) {
      return;
    }
    throw err;
  }

  throw new Error("external fetch to https://example.com succeeded; API interceptor is not active");
}
