import assert from "node:assert/strict";
import test from "node:test";
import { CyberLensClient } from "./client.js";

function jsonResponse(body: unknown, status: number = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function installMockFetch(
  handler: (input: string | URL | Request, init?: RequestInit) => Promise<Response>
): () => void {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = handler as typeof fetch;
  return () => {
    globalThis.fetch = originalFetch;
  };
}

test("scanWebsite forwards optional scan fields to the cloud API", async () => {
  let requestBody: Record<string, unknown> | undefined;
  const restoreFetch = installMockFetch(async (_input, init) => {
    requestBody = JSON.parse(String(init?.body));
    return jsonResponse({ data: { scan_id: "scan-website-123" } });
  });

  try {
    const client = new CyberLensClient("test-key", { apiBase: "https://api.example.com" });
    await client.scanWebsite({
      url: "https://example.com",
      scan_type: "database",
      database_connection: {
        provider: "postgres",
        connection_string: "postgres://demo",
      },
    });

    assert.deepEqual(requestBody, {
      url: "https://example.com",
      scan_type: "database",
      database_connection: {
        provider: "postgres",
        connection_string: "postgres://demo",
      },
    });
  } finally {
    restoreFetch();
  }
});

test("scanRepository forwards branch and depth to the cloud API", async () => {
  let requestBody: Record<string, unknown> | undefined;
  const restoreFetch = installMockFetch(async (_input, init) => {
    requestBody = JSON.parse(String(init?.body));
    return jsonResponse({ data: { scan_id: "scan-repo-123" } });
  });

  try {
    const client = new CyberLensClient("test-key", { apiBase: "https://api.example.com" });
    await client.scanRepository({
      repo_url: "https://github.com/example/repo",
      branch: "develop",
      depth: "deep",
    });

    assert.deepEqual(requestBody, {
      url: "https://github.com/example/repo",
      repo_url: "https://github.com/example/repo",
      branch: "develop",
      depth: "deep",
    });
  } finally {
    restoreFetch();
  }
});

test("getQuota maps the supported quota endpoint response", async () => {
  const restoreFetch = installMockFetch(async () =>
    jsonResponse({
      data: {
        plan: "agency",
        scans_used: 13,
        scans_limit: 750,
        scans_remaining: 737,
        website_scans_used: 5,
        website_scans_limit: 500,
        website_scans_remaining: 495,
        repo_scans_used: 6,
        repo_scans_limit: 250,
        repo_scans_remaining: 244,
        legacy_combined: false,
      },
    })
  );

  try {
    const client = new CyberLensClient("test-key", { apiBase: "https://api.example.com" });
    const quota = await client.getQuota();

    assert.deepEqual(quota, {
      plan: "agency",
      scans_used: 13,
      scans_limit: 750,
      scans_remaining: 737,
      website_scans_used: 5,
      website_scans_limit: 500,
      website_scans_remaining: 495,
      repo_scans_used: 6,
      repo_scans_limit: 250,
      repo_scans_remaining: 244,
      legacy_combined: false,
    });
  } finally {
    restoreFetch();
  }
});

test("getSecurityScore maps modern score and summary fields from the scan API", async () => {
  let pollCount = 0;
  const restoreFetch = installMockFetch(async (input) => {
    const url = String(input);

    if (url.endsWith("/scan")) {
      return jsonResponse({ data: { scan_id: "scan-score-123" } });
    }

    pollCount += 1;
    return jsonResponse({
      data: {
        status: "completed",
        scores: { overall: 52, database: null },
        summary: {
          total_tests: 34,
          vulnerabilities_found: 22,
          high: 9,
          medium: 10,
          low: 3,
        },
        vulnerabilities: [
          {
            passed: false,
            severity: "high",
            testId: "hsts_header",
            recommendation: "Add the Strict-Transport-Security header.",
          },
          {
            passed: false,
            severity: "medium",
            testId: "missing_csp",
            recommendation: "Add a Content-Security-Policy header.",
          },
        ],
      },
    });
  });

  try {
    const client = new CyberLensClient("test-key", { apiBase: "https://api.example.com", timeout: 5000 });
    const result = await client.getSecurityScore("https://example.com");

    assert.equal(pollCount, 1);
    assert.equal(result.score, 52);
    assert.equal(result.grade, "F");
    assert.match(result.summary, /34 tests run/);
    assert.deepEqual(result.quick_wins, [
      "Add the Strict-Transport-Security header.",
      "Add a Content-Security-Policy header.",
    ]);
  } finally {
    restoreFetch();
  }
});
