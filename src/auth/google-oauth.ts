import type { GoogleAccessToken, GoogleOAuthCredentials, GoogleOAuthRefreshOptions } from "./types";

const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const EXPIRY_SKEW_MS = 60_000;

export async function refreshGoogleAccessToken(
  credentials: GoogleOAuthCredentials,
  options: GoogleOAuthRefreshOptions = {},
): Promise<GoogleAccessToken> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? Date.now;
  const body = new URLSearchParams({
    client_id: credentials.clientId,
    client_secret: credentials.clientSecret,
    refresh_token: credentials.refreshToken,
    grant_type: "refresh_token",
  });

  const response = await fetchImpl(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body,
  });
  const text = await response.text();

  if (!response.ok) {
    options.logger?.warn?.(`google oauth refresh failed with ${response.status} ${response.statusText}`);
    throw new Error(`Google OAuth refresh failed (${response.status})`);
  }

  const parsed = JSON.parse(text) as Record<string, unknown>;
  const accessToken = typeof parsed.access_token === "string" ? parsed.access_token : undefined;
  const tokenType = typeof parsed.token_type === "string" ? parsed.token_type : "Bearer";
  const expiresIn = typeof parsed.expires_in === "number" ? parsed.expires_in : 3600;
  if (!accessToken) {
    throw new Error("Google OAuth refresh response missing access_token");
  }

  return {
    accessToken,
    tokenType,
    expiresAt: now() + expiresIn * 1000 - EXPIRY_SKEW_MS,
  };
}
