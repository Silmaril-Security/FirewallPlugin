export class SessionLock {
  private locked = new Set<string>();

  lock(sessionId: string | undefined): void {
    if (typeof sessionId === "string" && sessionId.length > 0) {
      this.locked.add(sessionId);
    }
  }

  isLocked(sessionId: string | undefined): boolean {
    return typeof sessionId === "string" && this.locked.has(sessionId);
  }
}
