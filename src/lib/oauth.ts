import OAuthClient from "intuit-oauth";

export function getCredentials(env?: string): { clientId: string; clientSecret: string } {
  const isProd = env === "production";
  const clientId = isProd
    ? (process.env.INTUIT_PROD_CLIENT_ID || process.env.INTUIT_CLIENT_ID)
    : (process.env.INTUIT_SANDBOX_CLIENT_ID || process.env.INTUIT_CLIENT_ID);
  const clientSecret = isProd
    ? (process.env.INTUIT_PROD_CLIENT_SECRET || process.env.INTUIT_CLIENT_SECRET)
    : (process.env.INTUIT_SANDBOX_CLIENT_SECRET || process.env.INTUIT_CLIENT_SECRET);

  if (!clientId || !clientSecret) {
    const label = isProd ? "production" : "sandbox";
    throw new Error(
      `Missing ${label} credentials. Run \`intuit auth configure --env ${label}\` to set them up.`
    );
  }

  return { clientId, clientSecret };
}

export function createOAuthClient(env?: string, redirectUri?: string) {
  const environment = env === "production" ? "production" : "sandbox";
  const { clientId, clientSecret } = getCredentials(env);

  return new OAuthClient({
    clientId,
    clientSecret,
    environment,
    redirectUri: redirectUri || "http://localhost:9477/callback",
    logging: false
  });
}

// Lifetime Intuit gives a refresh token (the x_refresh_token_expires_in in its
// token responses). Used only for tokens saved before refresh_expires_at was
// stored.
export const DEFAULT_REFRESH_TOKEN_LIFETIME_SECONDS = 8726400;

/**
 * Load a stored refresh token into the client before calling `oauth.refresh()`.
 *
 * intuit-oauth checks the refresh token's expiry locally before it calls Intuit
 * (`validateToken` → `isRefreshTokenValid`). With only `refresh_token` set, that
 * expiry is undefined, the check always fails, and every refresh throws "The
 * Refresh token is invalid, please Authorize again." without reaching Intuit.
 * So pass the token's remaining lifetime; Intuit still makes the final call.
 */
export function loadRefreshToken(
  oauth: OAuthClient,
  refreshToken: string,
  refreshExpiresAt?: number,
): void {
  const now = Date.now();
  const lifetimeSeconds = refreshExpiresAt !== undefined
    ? Math.floor((refreshExpiresAt - now) / 1000)
    : DEFAULT_REFRESH_TOKEN_LIFETIME_SECONDS;
  oauth.setToken({
    refresh_token: refreshToken,
    x_refresh_token_expires_in: lifetimeSeconds,
    createdAt: now,
  });
}

/** When a refresh token from an Intuit token response expires, in epoch ms. */
export function refreshExpiresAt(token: { x_refresh_token_expires_in?: number }): number {
  return Date.now() + (token.x_refresh_token_expires_in ?? DEFAULT_REFRESH_TOKEN_LIFETIME_SECONDS) * 1000;
}
