import { loadApiBaseUrl, loadApiKey, runConnectFlow } from "./auth.js";
import { CyberLensClient } from "./client.js";

export interface CloudClientContext<TClient = CyberLensClient> {
  client: TClient;
  connected_now: boolean;
  config_path?: string;
}

interface CloudClientDependencies<TClient> {
  loadApiKey?: () => string | null;
  loadApiBaseUrl?: () => string | null;
  runConnectFlow?: () => Promise<{ api_key: string; config_path: string }>;
  createClient?: (apiKey: string, options?: { apiBase?: string }) => TClient;
}

export async function getCloudClient<TClient = CyberLensClient>(
  dependencies: CloudClientDependencies<TClient> = {}
): Promise<CloudClientContext<TClient>> {
  const loadApiKeyFn = dependencies.loadApiKey ?? loadApiKey;
  const loadApiBaseUrlFn = dependencies.loadApiBaseUrl ?? loadApiBaseUrl;
  const runConnectFlowFn = dependencies.runConnectFlow ?? runConnectFlow;
  const createClientFn =
    dependencies.createClient ??
    ((apiKey: string, options?: { apiBase?: string }) =>
      new CyberLensClient(apiKey, options) as unknown as TClient);

  const create = (apiKey: string): TClient =>
    createClientFn(apiKey, { apiBase: loadApiBaseUrlFn() || undefined });

  const existingKey = loadApiKeyFn();
  if (existingKey) {
    return {
      client: create(existingKey),
      connected_now: false,
    };
  }

  const connection = await runConnectFlowFn();
  const connectedKey = loadApiKeyFn() || connection.api_key;
  if (!connectedKey) {
    throw new Error(
      "CyberLens account connection completed, but no API key was available afterward."
    );
  }

  return {
    client: create(connectedKey),
    connected_now: true,
    config_path: connection.config_path,
  };
}

export function getExistingCloudClient<TClient = CyberLensClient>(
  dependencies: CloudClientDependencies<TClient> = {}
): CloudClientContext<TClient> | null {
  const loadApiKeyFn = dependencies.loadApiKey ?? loadApiKey;
  const loadApiBaseUrlFn = dependencies.loadApiBaseUrl ?? loadApiBaseUrl;
  const createClientFn =
    dependencies.createClient ??
    ((apiKey: string, options?: { apiBase?: string }) =>
      new CyberLensClient(apiKey, options) as unknown as TClient);

  const existingKey = loadApiKeyFn();
  if (!existingKey) {
    return null;
  }

  return {
    client: createClientFn(existingKey, { apiBase: loadApiBaseUrlFn() || undefined }),
    connected_now: false,
  };
}
