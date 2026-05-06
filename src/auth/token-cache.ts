import type { GoogleAccessToken } from "./types";

export type GoogleTokenCache = {
  get(): Promise<GoogleAccessToken>;
};

export function createGoogleTokenCache(params: {
  refresh: () => Promise<GoogleAccessToken>;
  now?: () => number;
}): GoogleTokenCache {
  const now = params.now ?? Date.now;
  let cached: GoogleAccessToken | undefined;
  let inFlight: Promise<GoogleAccessToken> | undefined;

  return {
    async get() {
      if (cached && cached.expiresAt > now()) {
        return cached;
      }
      if (inFlight) {
        return inFlight;
      }

      inFlight = params.refresh()
        .then((token) => {
          cached = token;
          return token;
        })
        .finally(() => {
          inFlight = undefined;
        });
      return inFlight;
    },
  };
}
