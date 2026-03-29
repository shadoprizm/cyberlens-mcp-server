import assert from "node:assert/strict";
import test from "node:test";
import { CyberLensClient, CyberLensQuotaExceededError } from "./client.js";

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

test("scanRepository forwards repository scan fields to the public API", async () => {
  let requestBody: Record<string, unknown> | undefined;
  const restoreFetch = installMockFetch(async (_input, init) => {
    requestBody = JSON.parse(String(init?.body));
    return jsonResponse({ data: { scan_id: "scan-repo-123" } });
  });

  try {
    const client = new CyberLensClient("test-key", { apiBase: "https://api.example.com" });
    await client.scanRepository({
      repository_url: "https://github.com/openai/openai-node",
      depth: "deep",
      branch: "main",
    });

    assert.deepEqual(requestBody, {
      repo_url: "https://github.com/openai/openai-node",
      target_type: "repository",
      depth: "deep",
      branch: "main",
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
        upgrade_recommended: false,
        upgrade_url: "https://www.cyberlensai.com/pricing?source=api_quota_status&quota_type=combined#plans",
        website_upgrade_required: false,
        website_upgrade_url: "https://www.cyberlensai.com/pricing?source=api_quota_status&quota_type=website#plans",
        repo_upgrade_required: false,
        repo_upgrade_url: "https://www.cyberlensai.com/pricing?source=api_quota_status&quota_type=repository#plans",
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
        upgrade_recommended: false,
        upgrade_url: "https://www.cyberlensai.com/pricing?source=api_quota_status&quota_type=combined#plans",
        website_upgrade_required: false,
        website_upgrade_url: "https://www.cyberlensai.com/pricing?source=api_quota_status&quota_type=website#plans",
        repo_upgrade_required: false,
        repo_upgrade_url: "https://www.cyberlensai.com/pricing?source=api_quota_status&quota_type=repository#plans",
      });
  } finally {
    restoreFetch();
  }
});

test("scanWebsite throws a quota error with upgrade metadata when the scan limit is exhausted", async () => {
  const restoreFetch = installMockFetch(async () =>
    jsonResponse(
      {
        error: {
          code: "QUOTA_EXCEEDED",
          message: "Monthly website scan limit reached (5/5). Upgrade your plan to continue scanning immediately.",
          upgrade_url: "https://www.cyberlensai.com/pricing?source=api_quota_exceeded&quota_type=website#plans",
          quota_type: "website",
          used: 5,
          limit: 5,
        },
      },
      402
    )
  );

  try {
    const client = new CyberLensClient("test-key", { apiBase: "https://api.example.com" });
    await assert.rejects(
      () => client.scanWebsite({ url: "https://example.com", scan_type: "full" }),
      (error: unknown) => {
        assert.ok(error instanceof CyberLensQuotaExceededError);
        assert.equal(error.message, "Monthly website scan limit reached (5/5). Upgrade your plan to continue scanning immediately.");
        assert.equal(error.upgrade_url, "https://www.cyberlensai.com/pricing?source=api_quota_exceeded&quota_type=website#plans");
        assert.equal(error.quota_type, "website");
        assert.equal(error.used, 5);
        assert.equal(error.limit, 5);
        return true;
      }
    );
  } finally {
    restoreFetch();
  }
});

test("getScanResults maps repository-shaped scan responses", async () => {
  const restoreFetch = installMockFetch(async () =>
    jsonResponse({
      data: {
        scan_id: "scan-repo-results-123",
        url: "https://github.com/openai/openai-node",
        repository_url: "https://github.com/openai/openai-node",
        status: "completed",
        report_type: "repository_security_assessment",
        security_score: 88,
        repository_provider: "github",
        security_findings: [
          {
            severity: "high",
            testId: "hardcoded_secret",
            message: "Hardcoded secret detected",
            details: "Potential API key found in src/config.ts",
            recommendation: "Move the secret into environment variables.",
          },
        ],
        dependency_vulnerabilities: [
          {
            severity: "critical",
            package_name: "axios",
            current_version: "0.21.0",
            cve_ids: ["CVE-2024-0001"],
            remediation: "Upgrade axios to a patched release.",
          },
        ],
        trust_posture_findings: [
          {
            severity: "medium",
            title: "Unsigned release process",
            message: "Release artifacts are not signed.",
            remediation: "Sign releases before publication.",
          },
        ],
      },
    })
  );

  try {
    const client = new CyberLensClient("test-key", { apiBase: "https://api.example.com" });
    const result = await client.getScanResults("scan-repo-results-123");

    assert.equal(result.status, "completed");
    assert.equal(result.security_score, 88);
    assert.equal(result.findings.length, 3);
    assert.deepEqual(result.findings.map((finding) => finding.title), [
      "hardcoded_secret",
      "Dependency vulnerability: axios@0.21.0",
      "Unsigned release process",
    ]);
    assert.equal(result.findings[1].cwe, "CVE-2024-0001");
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
