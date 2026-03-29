export interface WebsiteFinding {
  type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  recommendation: string;
  evidence?: string;
}

export interface LocalWebsiteScanResult {
  source: "local";
  scan_mode: "local_quick";
  url: string;
  requested_scan_type: "quick" | "full" | "database";
  effective_scan_type: "quick";
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  findings: WebsiteFinding[];
  technologies: string[];
  scan_time_ms: number;
  warnings: string[];
  error?: string;
}

const RECOMMENDED_HEADERS: Record<
  string,
  {
    severity: WebsiteFinding["severity"];
    description: string;
    recommendation: string;
  }
> = {
  "content-security-policy": {
    severity: "medium",
    description: "Content-Security-Policy header is missing.",
    recommendation: "Add a Content-Security-Policy header to reduce XSS and injection risk.",
  },
  "strict-transport-security": {
    severity: "high",
    description: "HTTP Strict Transport Security (HSTS) is not enabled.",
    recommendation: "Add Strict-Transport-Security with a long max-age to force HTTPS.",
  },
  "x-frame-options": {
    severity: "medium",
    description: "X-Frame-Options header is missing.",
    recommendation: "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
  },
  "x-content-type-options": {
    severity: "low",
    description: "X-Content-Type-Options header is missing.",
    recommendation: "Add X-Content-Type-Options: nosniff to reduce MIME sniffing risk.",
  },
  "referrer-policy": {
    severity: "low",
    description: "Referrer-Policy header is missing.",
    recommendation: "Add Referrer-Policy: strict-origin-when-cross-origin.",
  },
  "permissions-policy": {
    severity: "low",
    description: "Permissions-Policy header is missing.",
    recommendation: "Add a restrictive Permissions-Policy header for browser APIs.",
  },
};

const TECH_SIGNATURES: Record<string, string[]> = {
  server: ["nginx", "apache", "cloudflare", "fastly", "akamai"],
  "x-powered-by": ["php", "asp.net", "express", "django", "rails"],
  "x-generator": ["wordpress", "drupal", "joomla", "next.js", "nuxt"],
};

const SEVERITY_WEIGHTS: Record<WebsiteFinding["severity"], number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

function buildWarnings(
  requestedScanType: "quick" | "full" | "database",
  databaseConnectionProvided: boolean
): string[] {
  const warnings: string[] = [
    "This was a local quick scan with roughly 15 core checks. Connect a CyberLens account for the full cloud scan with 70+ checks, scan history, and AI analysis.",
  ];

  if (requestedScanType !== "quick") {
    warnings.push(
      `Requested "${requestedScanType}" scan mode is only available in CyberLens cloud mode. The local quick scan was used instead.`
    );
  }

  if (requestedScanType === "database" || databaseConnectionProvided) {
    warnings.push("Database-specific checks only run in CyberLens cloud mode.");
  }

  return warnings;
}

function calculateScore(findings: WebsiteFinding[]): { score: number; grade: LocalWebsiteScanResult["grade"] } {
  let score = 100;
  for (const finding of findings) {
    score -= SEVERITY_WEIGHTS[finding.severity];
  }

  score = Math.max(0, Math.min(100, score));
  const grade: LocalWebsiteScanResult["grade"] =
    score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  return { score, grade };
}

function normalizeHeaders(headers: Headers): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [key, value] of headers.entries()) {
    normalized[key.toLowerCase()] = value;
  }
  return normalized;
}

function detectTechnologies(headers: Record<string, string>): string[] {
  const technologies = new Set<string>();

  for (const [header, signatures] of Object.entries(TECH_SIGNATURES)) {
    const value = headers[header];
    if (!value) continue;
    const lower = value.toLowerCase();
    for (const signature of signatures) {
      if (lower.includes(signature)) {
        technologies.add(signature);
      }
    }
  }

  const server = headers.server;
  if (server) {
    const normalized = server.includes("/") ? server.split("/")[0] : server.split(" ")[0];
    if (normalized) {
      technologies.add(normalized.toLowerCase());
    }
  }

  return [...technologies];
}

function checkHttps(url: string): WebsiteFinding[] {
  if (!url.startsWith("https://")) {
    return [
      {
        type: "no-https",
        severity: "critical",
        description: `Site does not use HTTPS: ${url}`,
        recommendation: "Enable HTTPS and redirect all HTTP traffic to HTTPS.",
      },
    ];
  }

  return [];
}

function checkHeaders(headers: Record<string, string>): WebsiteFinding[] {
  const findings: WebsiteFinding[] = [];

  for (const [header, config] of Object.entries(RECOMMENDED_HEADERS)) {
    const value = headers[header];
    if (!value) {
      findings.push({
        type: `missing-${header}`,
        severity: config.severity,
        description: config.description,
        recommendation: config.recommendation,
      });
      continue;
    }

    if (header === "x-frame-options") {
      const upper = value.toUpperCase();
      if (!["DENY", "SAMEORIGIN"].includes(upper)) {
        findings.push({
          type: "weak-x-frame-options",
          severity: "medium",
          description: `X-Frame-Options has a weak value: ${value}`,
          recommendation: "Use DENY or SAMEORIGIN for X-Frame-Options.",
          evidence: value,
        });
      }
    }
  }

  return findings;
}

function checkInformationDisclosure(headers: Record<string, string>): WebsiteFinding[] {
  const findings: WebsiteFinding[] = [];

  if (headers["x-powered-by"]) {
    findings.push({
      type: "information-disclosure",
      severity: "low",
      description: `X-Powered-By reveals technology: ${headers["x-powered-by"]}`,
      recommendation: "Remove the X-Powered-By header to reduce fingerprinting.",
      evidence: headers["x-powered-by"],
    });
  }

  const server = headers.server;
  if (server && server.includes("/") && /\d/.test(server)) {
    findings.push({
      type: "server-version-exposed",
      severity: "low",
      description: `Server version information is exposed: ${server}`,
      recommendation: "Configure the server to hide version numbers.",
      evidence: server,
    });
  }

  return findings;
}

function extractAttribute(tag: string, attribute: string): string {
  const escaped = attribute.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const doubleQuoted = new RegExp(`${escaped}\\s*=\\s*"([^"]*)"`, "i");
  const singleQuoted = new RegExp(`${escaped}\\s*=\\s*'([^']*)'`, "i");
  const unquoted = new RegExp(`${escaped}\\s*=\\s*([^\\s>]+)`, "i");

  const doubleMatch = tag.match(doubleQuoted);
  if (doubleMatch?.[1]) return doubleMatch[1];

  const singleMatch = tag.match(singleQuoted);
  if (singleMatch?.[1]) return singleMatch[1];

  const unquotedMatch = tag.match(unquoted);
  if (unquotedMatch?.[1]) return unquotedMatch[1];

  return "";
}

function analyzePage(html: string): WebsiteFinding[] {
  const findings: WebsiteFinding[] = [];

  const formRegex = /<form\b[^>]*>[\s\S]*?<\/form>/gi;
  const forms = html.match(formRegex) || [];
  for (const form of forms) {
    const action = extractAttribute(form, "action");
    const method = (extractAttribute(form, "method") || "get").toLowerCase();

    if (action.startsWith("http://")) {
      findings.push({
        type: "insecure-form-action",
        severity: "high",
        description: `Form submits to an insecure HTTP endpoint: ${action}`,
        recommendation: "Update the form action to use HTTPS.",
        evidence: action,
      });
    }

    if (method === "post") {
      const hasCsrfToken = /\bname\s*=\s*["'](?:csrf|csrf_token|_token|authenticity_token)["']/i.test(form);
      if (!hasCsrfToken) {
        findings.push({
          type: "missing-csrf-protection",
          severity: "medium",
          description: "POST form without an obvious CSRF token detected.",
          recommendation: "Add CSRF tokens to state-changing forms.",
        });
      }
    }
  }

  const inlineScripts = html.match(/<script\b(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/gi) || [];
  if (inlineScripts.length > 5) {
    findings.push({
      type: "many-inline-scripts",
      severity: "info",
      description: `Found ${inlineScripts.length} inline script blocks.`,
      recommendation: "Move inline scripts into external files and pair them with a CSP.",
      evidence: `${inlineScripts.length} inline scripts`,
    });
  }

  return findings;
}

export async function scanWebsiteLocally(
  url: string,
  options: {
    timeoutMs?: number;
    requestedScanType?: "quick" | "full" | "database";
    databaseConnectionProvided?: boolean;
  } = {}
): Promise<LocalWebsiteScanResult> {
  const startedAt = Date.now();
  const requestedScanType = options.requestedScanType ?? "full";
  const warnings = buildWarnings(requestedScanType, options.databaseConnectionProvided ?? false);

  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    return {
      source: "local",
      scan_mode: "local_quick",
      url,
      requested_scan_type: requestedScanType,
      effective_scan_type: "quick",
      score: 0,
      grade: "F",
      findings: [],
      technologies: [],
      scan_time_ms: Date.now() - startedAt,
      warnings,
      error: "URL must start with http:// or https://",
    };
  }

  try {
    const response = await fetch(url, {
      redirect: "follow",
      signal: AbortSignal.timeout(options.timeoutMs ?? 30_000),
      headers: {
        "User-Agent": "CyberLens-MCP/1.0.0",
      },
    });

    const headers = normalizeHeaders(response.headers);
    const finalUrl = response.url || url;
    const html = await response.text().catch(() => "");
    const findings = [
      ...checkHttps(finalUrl),
      ...checkHeaders(headers),
      ...checkInformationDisclosure(headers),
      ...analyzePage(html),
    ];
    const { score, grade } = calculateScore(findings);

    return {
      source: "local",
      scan_mode: "local_quick",
      url: finalUrl,
      requested_scan_type: requestedScanType,
      effective_scan_type: "quick",
      score,
      grade,
      findings,
      technologies: detectTechnologies(headers),
      scan_time_ms: Date.now() - startedAt,
      warnings,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      source: "local",
      scan_mode: "local_quick",
      url,
      requested_scan_type: requestedScanType,
      effective_scan_type: "quick",
      score: 0,
      grade: "F",
      findings: [],
      technologies: [],
      scan_time_ms: Date.now() - startedAt,
      warnings,
      error: message,
    };
  }
}
