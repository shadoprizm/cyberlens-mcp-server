import assert from "node:assert/strict";
import test from "node:test";
import { scanWebsiteLocally } from "./website-scanner.js";

function htmlResponse(html: string, url: string, headers: Record<string, string> = {}): Response {
  return new Response(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      ...headers,
    },
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

test("scanWebsiteLocally warns when a cloud-only scan type is requested", async () => {
  const restoreFetch = installMockFetch(async () =>
    htmlResponse("<html><body>Hello</body></html>", "https://example.com", {
      "Strict-Transport-Security": "max-age=31536000",
      "Content-Security-Policy": "default-src 'self'",
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Permissions-Policy": "camera=()",
    })
  );

  try {
    const result = await scanWebsiteLocally("https://example.com", {
      requestedScanType: "full",
    });

    assert.equal(result.source, "local");
    assert.equal(result.scan_mode, "local_quick");
    assert.equal(result.effective_scan_type, "quick");
    assert.match(result.warnings.join("\n"), /full" scan mode is only available/i);
  } finally {
    restoreFetch();
  }
});

test("scanWebsiteLocally reports common header and form findings", async () => {
  const html = `
    <html>
      <body>
        <form method="post" action="http://example.com/login">
          <input name="email" />
        </form>
        <script>console.log(1)</script>
        <script>console.log(2)</script>
        <script>console.log(3)</script>
        <script>console.log(4)</script>
        <script>console.log(5)</script>
        <script>console.log(6)</script>
      </body>
    </html>
  `;

  const restoreFetch = installMockFetch(async () =>
    htmlResponse(html, "http://example.com", {
      Server: "nginx/1.25.0",
      "X-Powered-By": "Express",
    })
  );

  try {
    const result = await scanWebsiteLocally("http://example.com", {
      requestedScanType: "quick",
    });

    assert.equal(result.url, "http://example.com");
    assert.ok(result.findings.some((finding) => finding.type === "no-https"));
    assert.ok(result.findings.some((finding) => finding.type === "missing-content-security-policy"));
    assert.ok(result.findings.some((finding) => finding.type === "insecure-form-action"));
    assert.ok(result.findings.some((finding) => finding.type === "missing-csrf-protection"));
    assert.ok(result.findings.some((finding) => finding.type === "many-inline-scripts"));
    assert.ok(result.findings.some((finding) => finding.type === "server-version-exposed"));
    assert.ok(result.technologies.includes("nginx"));
    assert.ok(result.technologies.includes("express"));
    assert.equal(result.grade, "F");
  } finally {
    restoreFetch();
  }
});
