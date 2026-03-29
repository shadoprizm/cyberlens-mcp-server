/**
 * Browser-based authentication flow for CyberLens account connection.
 * TypeScript port of the CyberLens skill's auth.py pattern.
 */

import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { URL, URLSearchParams } from "node:url";
import { exec } from "node:child_process";

const CONNECT_BASE_URL = "https://cyberlensai.com/connect";
const PRICING_BASE_URL = "https://www.cyberlensai.com/pricing";
const TRUSTED_EXCHANGE_HOSTS = new Set([
  "cyberlensai.com",
  "www.cyberlensai.com",
  "api.cyberlensai.com",
]);

const CONFIG_DIR = join(homedir(), ".cyberlens", "mcp");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");

// ---- Config file helpers ----

function loadLocalConfig(): Record<string, any> {
  if (!existsSync(CONFIG_FILE)) return {};
  try {
    return JSON.parse(readFileSync(CONFIG_FILE, "utf-8"));
  } catch {
    return {};
  }
}

function writeLocalConfig(config: Record<string, any>): string {
  mkdirSync(CONFIG_DIR, { recursive: true });
  try {
    chmodSync(CONFIG_DIR, 0o700);
  } catch {}

  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), "utf-8");
  try {
    chmodSync(CONFIG_FILE, 0o600);
  } catch {}

  return CONFIG_FILE;
}

export function saveApiKey(key: string): string {
  const config = loadLocalConfig();
  config.api_key = key;
  return writeLocalConfig(config);
}

export function loadApiKey(): string | null {
  // Environment variable takes priority
  const envKey = process.env.CYBERLENS_API_KEY;
  if (envKey) return envKey;

  // Then config file
  return loadLocalConfig().api_key || null;
}

export function loadApiBaseUrl(): string | null {
  const envBase = (process.env.CYBERLENS_API_BASE_URL || "").trim();
  if (envBase) return envBase;

  const configured = loadLocalConfig().api_base_url;
  if (typeof configured === "string" && configured.trim()) return configured.trim();

  return null;
}

// ---- Host validation ----

function isTrustedExchangeHost(hostname: string | null): boolean {
  if (!hostname) return false;
  return TRUSTED_EXCHANGE_HOSTS.has(hostname) || hostname.endsWith(".cyberlensai.com");
}

// ---- Browser open (cross-platform) ----

function openBrowser(url: string): void {
  const cmd =
    process.platform === "darwin"
      ? `open "${url}"`
      : process.platform === "win32"
        ? `start "" "${url}"`
        : `xdg-open "${url}"`;
  exec(cmd, () => {});
}

export function buildUpgradeUrl(quotaType: "website" | "repository" | "combined" = "combined"): string {
  const url = new URL(PRICING_BASE_URL);
  url.searchParams.set("source", "mcp-quota-exceeded");
  url.searchParams.set("quota_type", quotaType);
  url.hash = "plans";
  return url.toString();
}

export function openUpgradePage(url: string): void {
  openBrowser(url);
}

// ---- Port finding ----

function findOpenPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr && typeof addr === "object") {
        const port = addr.port;
        server.close(() => resolve(port));
      } else {
        server.close(() => reject(new Error("Could not find open port")));
      }
    });
    server.on("error", reject);
  });
}

// ---- Code exchange ----

async function exchangeConnectCode(code: string, exchangeUrl: string): Promise<string> {
  const parsed = new URL(exchangeUrl);
  if (parsed.protocol !== "https:") {
    throw new Error("Invalid exchange URL returned by CyberLens.");
  }
  if (!isTrustedExchangeHost(parsed.hostname)) {
    throw new Error(`CyberLens returned an untrusted exchange host: ${parsed.hostname}`);
  }

  const response = await fetch(exchangeUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code }),
    signal: AbortSignal.timeout(15_000),
  });

  let payload: any = {};
  try {
    payload = await response.json();
  } catch {}

  if (response.status === 404) {
    throw new Error("CyberLens connect code was not found. Please try again.");
  }
  if (response.status === 409) {
    throw new Error("CyberLens connect code was already used. Please reconnect.");
  }
  if (response.status === 410) {
    throw new Error("CyberLens connect code expired. Please reconnect.");
  }
  if (!response.ok) {
    throw new Error(payload.error || `Exchange failed with status ${response.status}.`);
  }

  const fullKey = payload.fullKey;
  if (!fullKey) {
    throw new Error("CyberLens exchange response did not include an API key.");
  }

  return fullKey;
}

// ---- Connect flow ----

export async function runConnectFlow(): Promise<{
  api_key: string;
  config_path: string;
}> {
  const state = randomBytes(32).toString("base64url");
  const port = await findOpenPort();
  const callbackUrl = `http://localhost:${port}/callback`;

  return new Promise((resolve, reject) => {
    let connectCode: string | null = null;
    let exchangeUrl: string | null = null;
    let callbackError: string | null = null;
    let received = false;
    const timeout = 300_000; // 5 minutes

    const server = createServer((req: IncomingMessage, res: ServerResponse) => {
      if (!req.url) return;
      const parsed = new URL(req.url, `http://localhost:${port}`);

      const reqState = parsed.searchParams.get("state");
      const reqCode = parsed.searchParams.get("code");
      const reqExchange = parsed.searchParams.get("exchange");
      const reqError = parsed.searchParams.get("error");

      if (reqState !== state) {
        res.writeHead(400, { "Content-Type": "text/plain" });
        res.end("Invalid callback. State mismatch.");
        return;
      }

      if (reqError) {
        callbackError = reqError;
        received = true;
        res.writeHead(400, { "Content-Type": "text/plain" });
        res.end(`Connection failed: ${reqError}`);
        finalize();
        return;
      }

      if (reqCode && reqExchange) {
        connectCode = reqCode;
        exchangeUrl = reqExchange;
        received = true;
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(
          '<html><body style="font-family:system-ui;background:#1a1a2e;color:white;' +
            'display:flex;align-items:center;justify-content:center;height:100vh;margin:0">' +
            '<div style="text-align:center">' +
            "<h1>&#x2705; Authorization Received</h1>" +
            "<p>You can close this tab. The MCP server is finishing the secure exchange.</p>" +
            "</div></body></html>"
        );
        finalize();
        return;
      }

      callbackError = "Missing exchange code.";
      received = true;
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("Invalid callback. Missing exchange code.");
      finalize();
    });

    const timer = setTimeout(() => {
      if (!received) {
        server.close();
        reject(
          new Error(
            "Did not receive a CyberLens connect code within 5 minutes. " +
              "Please try again or set CYBERLENS_API_KEY manually."
          )
        );
      }
    }, timeout);

    async function finalize() {
      clearTimeout(timer);
      server.close();

      if (callbackError) {
        reject(new Error(`CyberLens connection failed: ${callbackError}`));
        return;
      }

      if (!connectCode || !exchangeUrl) {
        reject(new Error("Missing connect code or exchange URL."));
        return;
      }

      try {
        const apiKey = await exchangeConnectCode(connectCode, exchangeUrl);
        const configPath = saveApiKey(apiKey);
        resolve({ api_key: apiKey, config_path: configPath });
      } catch (err) {
        reject(err);
      }
    }

    server.listen(port, "127.0.0.1", () => {
      const params = new URLSearchParams({
        client: "cyberlens_cli",
        callback: callbackUrl,
        state,
      });
      const connectUrl = `${CONNECT_BASE_URL}?${params.toString()}`;

      // Log to stderr so it doesn't interfere with MCP stdio
      console.error(`\nComplete CyberLens connection in your browser: ${connectUrl}\n`);
      openBrowser(connectUrl);
    });

    server.on("error", (err) => {
      clearTimeout(timer);
      reject(new Error(`Failed to start callback server: ${err.message}`));
    });
  });
}
