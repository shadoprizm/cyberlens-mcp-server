import assert from "node:assert/strict";
import test from "node:test";
import { getCloudClient, getExistingCloudClient } from "./cloud-client.js";

test("getCloudClient reuses an existing API key without opening the browser flow", async () => {
  let connectCalls = 0;
  let receivedKey: string | undefined;
  let receivedApiBase: string | undefined;

  const result = await getCloudClient({
    loadApiKey: () => "existing-key",
    loadApiBaseUrl: () => "https://api.example.com",
    runConnectFlow: async () => {
      connectCalls += 1;
      return { api_key: "new-key", config_path: "/tmp/config.json" };
    },
    createClient: (apiKey, options) => {
      receivedKey = apiKey;
      receivedApiBase = options?.apiBase;
      return { apiKey, apiBase: options?.apiBase };
    },
  });

  assert.equal(connectCalls, 0);
  assert.equal(receivedKey, "existing-key");
  assert.equal(receivedApiBase, "https://api.example.com");
  assert.equal(result.connected_now, false);
  assert.deepEqual(result.client, {
    apiKey: "existing-key",
    apiBase: "https://api.example.com",
  });
});

test("getCloudClient auto-connects when the API key is missing", async () => {
  let connectCalls = 0;
  let loadCalls = 0;

  const result = await getCloudClient({
    loadApiKey: () => {
      loadCalls += 1;
      return loadCalls >= 2 ? "saved-key" : null;
    },
    loadApiBaseUrl: () => null,
    runConnectFlow: async () => {
      connectCalls += 1;
      return { api_key: "connected-key", config_path: "/tmp/cyberlens.json" };
    },
    createClient: (apiKey) => ({ apiKey }),
  });

  assert.equal(connectCalls, 1);
  assert.equal(result.connected_now, true);
  assert.equal(result.config_path, "/tmp/cyberlens.json");
  assert.deepEqual(result.client, { apiKey: "saved-key" });
});

test("getCloudClient falls back to the freshly returned key when the saved key is not yet readable", async () => {
  const result = await getCloudClient({
    loadApiKey: () => null,
    loadApiBaseUrl: () => null,
    runConnectFlow: async () => ({
      api_key: "fresh-key",
      config_path: "/tmp/cyberlens.json",
    }),
    createClient: (apiKey) => ({ apiKey }),
  });

  assert.equal(result.connected_now, true);
  assert.equal(result.config_path, "/tmp/cyberlens.json");
  assert.deepEqual(result.client, { apiKey: "fresh-key" });
});

test("getExistingCloudClient returns null when the API key is missing", () => {
  const result = getExistingCloudClient({
    loadApiKey: () => null,
    loadApiBaseUrl: () => null,
    createClient: (apiKey) => ({ apiKey }),
  });

  assert.equal(result, null);
});

test("getExistingCloudClient returns a client without auto-connecting", () => {
  const result = getExistingCloudClient({
    loadApiKey: () => "existing-key",
    loadApiBaseUrl: () => "https://api.example.com",
    createClient: (apiKey, options) => ({ apiKey, apiBase: options?.apiBase }),
  });

  assert.deepEqual(result, {
    client: { apiKey: "existing-key", apiBase: "https://api.example.com" },
    connected_now: false,
  });
});
