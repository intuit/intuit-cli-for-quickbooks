import { describe, it, expect } from "vitest";
import OAuthClient from "intuit-oauth";
import {
  DEFAULT_REFRESH_TOKEN_LIFETIME_SECONDS,
  loadRefreshToken,
  refreshExpiresAt,
} from "../lib/oauth.js";

// validateToken() is the local check intuit-oauth runs at the start of refresh(),
// before any network call. The client is only constructed, never used to call Intuit.
type ValidatingClient = OAuthClient & { validateToken(): void };

function client(): ValidatingClient {
  return new OAuthClient({
    clientId: "test-client-id",
    clientSecret: "test-client-secret",
    environment: "sandbox",
    redirectUri: "http://localhost:9477/callback",
  }) as ValidatingClient;
}

const DAY_MS = 24 * 60 * 60 * 1000;

describe("loadRefreshToken", () => {
  it("setting only refresh_token makes intuit-oauth reject it locally (the bug)", () => {
    const oauth = client();
    oauth.setToken({ refresh_token: "rt" });
    expect(() => oauth.validateToken(), "bare setToken should fail validateToken")
      .toThrow("The Refresh token is invalid, please Authorize again.");
  });

  it("accepts a refresh token with a stored expiry in the future", () => {
    const oauth = client();
    loadRefreshToken(oauth, "rt", Date.now() + 30 * DAY_MS);
    expect(() => oauth.validateToken(), "an unexpired token must pass the local check").not.toThrow();
  });

  it("accepts a token saved without an expiry by falling back to Intuit's lifetime", () => {
    const oauth = client();
    loadRefreshToken(oauth, "rt");
    expect(() => oauth.validateToken(), "legacy tokens must still refresh").not.toThrow();
  });

  it("still rejects a refresh token whose stored expiry has passed", () => {
    const oauth = client();
    loadRefreshToken(oauth, "rt", Date.now() - DAY_MS);
    expect(() => oauth.validateToken(), "an expired token should ask the user to log in again")
      .toThrow("The Refresh token is invalid, please Authorize again.");
  });
});

describe("refreshExpiresAt", () => {
  it("uses x_refresh_token_expires_in from the token response", () => {
    const before = Date.now();
    const at = refreshExpiresAt({ x_refresh_token_expires_in: 1000 });
    expect(at - before, "expiry should be ~1000s from now").toBeGreaterThanOrEqual(1000 * 1000);
    expect(at - before).toBeLessThan(1000 * 1000 + 1000);
  });

  it("falls back to the default lifetime when the response omits it", () => {
    const before = Date.now();
    const at = refreshExpiresAt({});
    expect(at - before).toBeGreaterThanOrEqual(DEFAULT_REFRESH_TOKEN_LIFETIME_SECONDS * 1000);
  });
});
