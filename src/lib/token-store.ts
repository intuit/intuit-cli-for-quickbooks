import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { createOAuthClient, loadRefreshToken, refreshExpiresAt } from "./oauth.js";
import { getOrCreateKey, deleteKey } from "./keychain.js";
import { configureTls } from "./tls.js";

export type TokenData = {
  access_token?: string;
  refresh_token?: string;
  realmId?: string;
  expires_at?: number;
  /** When the refresh token expires, in epoch ms. Absent on tokens saved by older versions. */
  refresh_expires_at?: number;
  /**
   * Full list of OAuth scope strings requested at login time. Intuit's OAuth
   * response doesn't return a granted-scope field, so we track what we asked
   * for instead. If a scope wasn't granted, the OAuth request would have
   * failed before this token was created.
   */
  requestedScopes?: string[];
};

type EncryptedPayload = {
  iv: string;
  tag: string;
  data: string;
};

export type ProfileInfo = {
  name: string;
  env: string;
  realmId?: string;
};

type ProfilesConfig = {
  active: string;
  profiles: Record<string, ProfileInfo>;
};

const TOKEN_DIR = path.join(os.homedir(), ".config", "intuit-cli");
const PROFILES_PATH = path.join(TOKEN_DIR, "profiles.json");

function tokenPath(profile: string): string {
  return path.join(TOKEN_DIR, `${profile}.tokens.enc.json`);
}

function encrypt(plaintext: string, profile: string): EncryptedPayload {
  const key = getOrCreateKey(profile);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  let encrypted = cipher.update(plaintext, "utf-8", "hex");
  encrypted += cipher.final("hex");
  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString("hex"),
    tag: tag.toString("hex"),
    data: encrypted
  };
}

function decrypt(payload: EncryptedPayload, profile: string): string {
  const key = getOrCreateKey(profile);
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(payload.iv, "hex")
  );
  decipher.setAuthTag(Buffer.from(payload.tag, "hex"));

  let decrypted = decipher.update(payload.data, "hex", "utf-8");
  decrypted += decipher.final("utf-8");
  return decrypted;
}

function loadProfiles(): ProfilesConfig {
  try {
    const raw = fs.readFileSync(PROFILES_PATH, "utf-8");
    return JSON.parse(raw) as ProfilesConfig;
  } catch {
    return { active: "default", profiles: {} };
  }
}

function saveProfiles(config: ProfilesConfig) {
  fs.mkdirSync(TOKEN_DIR, { recursive: true });
  fs.writeFileSync(PROFILES_PATH, JSON.stringify(config, null, 2), { mode: 0o600 });
}

export const profileStore = {
  getActive(): string {
    return process.env.INTUIT_PROFILE || loadProfiles().active;
  },

  getInfo(profile?: string): ProfileInfo | null {
    const p = profile || this.getActive();
    const config = loadProfiles();
    return config.profiles[p] || null;
  },

  setActive(profile: string) {
    const config = loadProfiles();
    if (!config.profiles[profile]) {
      throw new Error(`Profile "${profile}" does not exist. Run \`intuit profile list\` to see available profiles.`);
    }
    config.active = profile;
    saveProfiles(config);
  },

  add(profile: string, env: string, realmId?: string) {
    const config = loadProfiles();
    config.profiles[profile] = { name: profile, env, realmId };
    if (Object.keys(config.profiles).length === 1) {
      config.active = profile;
    }
    saveProfiles(config);
  },

  remove(profile: string) {
    const config = loadProfiles();
    delete config.profiles[profile];
    if (config.active === profile) {
      const remaining = Object.keys(config.profiles);
      config.active = remaining[0] || "default";
    }
    saveProfiles(config);
    tokenStore.clear(profile);
  },

  list(): (ProfileInfo & { active: boolean })[] {
    const config = loadProfiles();
    return Object.entries(config.profiles).map(([key, val]) => ({
      ...val,
      name: key,
      active: key === config.active
    }));
  }
};

export const tokenStore = {
  get(profile?: string): TokenData | null {
    const p = profile || profileStore.getActive();
    try {
      const raw = fs.readFileSync(tokenPath(p), "utf-8");
      const payload = JSON.parse(raw) as EncryptedPayload;
      const decrypted = decrypt(payload, p);
      return JSON.parse(decrypted) as TokenData;
    } catch {
      return null;
    }
  },

  set(data: TokenData, profile?: string) {
    const p = profile || profileStore.getActive();
    fs.mkdirSync(TOKEN_DIR, { recursive: true });
    const payload = encrypt(JSON.stringify(data), p);
    fs.writeFileSync(tokenPath(p), JSON.stringify(payload, null, 2), { mode: 0o600 });
  },

  clear(profile?: string) {
    const p = profile || profileStore.getActive();
    try {
      fs.unlinkSync(tokenPath(p));
    } catch {
      // file doesn't exist
    }
    deleteKey(p);
  },

  async getValidToken(profile?: string): Promise<TokenData> {
    const p = profile || profileStore.getActive();
    const token = this.get(p);
    if (!token?.access_token || !token.realmId) {
      throw new Error("Not authenticated. Run `intuit auth login` first.");
    }

    if (token.expires_at && Date.now() >= token.expires_at) {
      return this.refreshToken(token, p);
    }

    return token;
  },

  async refreshToken(token: TokenData, profile?: string): Promise<TokenData> {
    const p = profile || profileStore.getActive();
    if (!token.refresh_token) {
      throw new Error("Token expired and no refresh token available. Run `intuit auth login`.");
    }

    const info = profileStore.getInfo(p);
    configureTls();
    const oauth = createOAuthClient(info?.env);
    loadRefreshToken(oauth, token.refresh_token, token.refresh_expires_at);

    const authResponse = await oauth.refresh();
    const refreshed: TokenData = {
      access_token: authResponse.token.access_token,
      refresh_token: authResponse.token.refresh_token,
      realmId: token.realmId,
      expires_at: Date.now() + 3600 * 1000,
      refresh_expires_at: refreshExpiresAt(authResponse.token),
      // Refresh tokens inherit the original token's scope set — preserve so
      // auth status / Premium checks survive auto-refresh.
      requestedScopes: token.requestedScopes,
    };
    this.set(refreshed, p);
    console.log("Token refreshed automatically.");
    return refreshed;
  }
};
