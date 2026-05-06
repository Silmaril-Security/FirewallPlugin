import type { Logger } from "../core";

export type GoogleOAuthCredentials = {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
};

export type GoogleAccessToken = {
  accessToken: string;
  tokenType: string;
  expiresAt: number;
};

export type GoogleOAuthRefreshOptions = {
  fetchImpl?: typeof fetch;
  logger?: Logger;
  now?: () => number;
};
