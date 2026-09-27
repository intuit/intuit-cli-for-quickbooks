import http from "node:http";
import crypto from "node:crypto";
import OAuthClient from "intuit-oauth";
import { createOAuthClient, refreshExpiresAt } from "../lib/oauth.js";
import { tokenStore, profileStore } from "../lib/token-store.js";
import { configureTls } from "../lib/tls.js";
const CALLBACK_TIMEOUT_MS = 120_000; // 2 minutes
const DEFAULT_REDIRECT_URI = "http://localhost:9477/callback";
function waitForCallback(port, pathname, expectedState) {
    return new Promise((resolve, reject) => {
        const server = http.createServer((req, res) => {
            const url = new URL(req.url ?? "/", `http://localhost:${port}`);
            if (url.pathname !== pathname) {
                res.writeHead(404);
                res.end("Not found");
                return;
            }
            const error = url.searchParams.get("error");
            if (error) {
                const desc = url.searchParams.get("error_description") ?? error;
                res.writeHead(200, { "Content-Type": "text/html" });
                res.end(`<html><body><h1>Authentication Failed</h1><p>${desc}</p><p>You can close this window.</p></body></html>`);
                clearTimeout(timeout);
                server.close();
                reject(new Error(`OAuth error: ${desc}`));
                return;
            }
            // Step 3: Verify state before calling createToken — CSRF protection
            const returnedState = url.searchParams.get("state");
            if (!returnedState || !crypto.timingSafeEqual(Buffer.from(returnedState), Buffer.from(expectedState))) {
                res.writeHead(200, { "Content-Type": "text/html" });
                res.end(`<html><body><h1>Authentication Failed</h1><p>Invalid state parameter. Possible CSRF attempt.</p><p>You can close this window.</p></body></html>`);
                clearTimeout(timeout);
                server.close();
                reject(new Error("OAuth state mismatch — possible CSRF attack. Please try again."));
                return;
            }
            res.writeHead(200, { "Content-Type": "text/html", Connection: "close" });
            res.end(`<html><body><h1>Success!</h1><p>You are now logged in. You can close this window.</p></body></html>`, () => {
                clearTimeout(timeout);
                server.close();
                resolve(req.url);
            });
        });
        const timeout = setTimeout(() => {
            server.close();
            reject(new Error("OAuth callback timed out after 2 minutes. Please try again."));
        }, CALLBACK_TIMEOUT_MS);
        server.on("error", (err) => {
            clearTimeout(timeout);
            if (err.code === "EADDRINUSE") {
                reject(new Error(`Port ${port} is already in use. Close the other process and try again.`));
            }
            else {
                reject(err);
            }
        });
        server.listen(port, "127.0.0.1", () => {
            console.log(`Listening on http://localhost:${port}${pathname}`);
        });
    });
}
// Known Premium OAuth scope strings, for validation only. The .env value is
// passed through to Intuit verbatim, but if a scope isn't in this set we warn
// — likely a typo, but conceivably a new Premium scope Intuit added.
const KNOWN_PREMIUM_SCOPES = new Set([
    OAuthClient.scopes.ProjectManagement,
    OAuthClient.scopes.CustomFields,
    OAuthClient.scopes.Dimensions,
]);
/**
 * Read the user's configured Premium scope strings from the .env-backed env
 * var for this environment. The var holds raw OAuth scope strings (e.g.
 * "project-management.project") separated by spaces or commas. Unknown scope
 * strings produce a warning but are still passed through.
 */
function readEnvPremiumScopes(env) {
    const isProd = env === "production";
    const raw = isProd
        ? process.env.INTUIT_PROD_PREMIUM_SCOPES
        : process.env.INTUIT_SANDBOX_PREMIUM_SCOPES;
    if (!raw)
        return [];
    // Accept space- or comma-separated. OAuth scope is space-delimited per
    // RFC 6749 but partners often default to comma — handle both.
    const scopes = raw.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
    const unknown = scopes.filter((s) => !KNOWN_PREMIUM_SCOPES.has(s));
    if (unknown.length > 0) {
        console.error(`⚠  Unknown Premium scope(s) in .env: ${unknown.join(", ")}`);
        console.error(`   Known Premium scopes: ${[...KNOWN_PREMIUM_SCOPES].join(", ")}`);
        console.error(`   The scopes will still be sent to Intuit; this is a warning, not an error.`);
    }
    return scopes;
}
export async function authLogin(profile, env, redirectUri, extraScopes = []) {
    configureTls();
    const callbackUri = redirectUri || DEFAULT_REDIRECT_URI;
    if (env === "production" && !redirectUri) {
        throw new Error("Production requires --redirect-uri with a registered HTTPS URL.\nExample: intuit auth login --profile prod --env production --redirect-uri https://yourapp.com/callback");
    }
    const state = crypto.randomBytes(16).toString("hex");
    const oauth = createOAuthClient(env, callbackUri);
    // Premium scopes are app-level config that pairs with the client_id/secret.
    // Set INTUIT_<env>_PREMIUM_SCOPES in .env (space- or comma-separated raw
    // OAuth scope strings) to opt in. Apps without Premium approval should
    // leave it empty — Intuit will reject the OAuth flow if unapproved scopes
    // are requested.
    const premiumScopes = readEnvPremiumScopes(env);
    const requestedScopes = [
        OAuthClient.scopes.Accounting,
        OAuthClient.scopes.OpenId,
        ...premiumScopes,
        ...extraScopes,
    ];
    const authUri = oauth.authorizeUri({ scope: requestedScopes, state });
    const redirectUrl = new URL(callbackUri);
    const port = parseInt(redirectUrl.port || "9477", 10);
    console.log(`\nProfile: ${profile} | Environment: ${env}`);
    console.log("\nOpen this URL in your browser:\n");
    console.log(authUri);
    console.log("");
    const callbackUrl = await waitForCallback(port, redirectUrl.pathname, state);
    const authResponse = await oauth.createToken(callbackUrl);
    const realmId = authResponse.token.realmId;
    // Intuit's OAuth response doesn't include a granted-scope field — track
    // what we requested. If a scope wasn't granted, the request would have
    // failed before reaching this point.
    tokenStore.set({
        access_token: authResponse.token.access_token,
        refresh_token: authResponse.token.refresh_token,
        realmId,
        expires_at: Date.now() + 3600 * 1000,
        refresh_expires_at: refreshExpiresAt(authResponse.token),
        requestedScopes,
    }, profile);
    profileStore.add(profile, env, realmId);
    profileStore.setActive(profile);
    console.log(`\nLogin successful. Profile: ${profile} (now active), Env: ${env}, Realm: ${realmId}`);
    if (premiumScopes.length > 0) {
        console.log(`Premium scopes: ${premiumScopes.join(" ")}`);
    }
    process.exit(0);
}
