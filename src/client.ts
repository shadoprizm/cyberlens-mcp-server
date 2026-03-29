/**
 * Cyber Lens AI API Client
 * REST API client using X-API-Key authentication.
 * Matches the CyberLens skill's public scan API surface.
 */

import { ScanRepositoryArgs, ScanWebsiteArgs } from "./schemas.js";

const DEFAULT_API_BASE = "https://api.cyberlensai.com/functions/v1/public-api-scan";

export class CyberLensQuotaExceededError extends Error {
  readonly code = "QUOTA_EXCEEDED";
  readonly upgrade_url?: string;
  readonly quota_type?: "website" | "repository" | "combined";
  readonly used?: number;
  readonly limit?: number;

  constructor(
    message: string,
    options?: {
      upgrade_url?: string;
      quota_type?: "website" | "repository" | "combined";
      used?: number;
      limit?: number;
    }
  ) {
    super(message);
    this.name = "CyberLensQuotaExceededError";
    this.upgrade_url = options?.upgrade_url;
    this.quota_type = options?.quota_type;
    this.used = options?.used;
    this.limit = options?.limit;
  }
}

function resolveApiBase(apiBase?: string): string {
  const candidate = (apiBase || process.env.CYBERLENS_API_BASE_URL || DEFAULT_API_BASE).trim();
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol !== "https:") {
      throw new Error("CyberLens API base URL must use HTTPS.");
    }
  } catch (e) {
    if (e instanceof TypeError) {
      throw new Error("CyberLens API base URL is not a valid URL.");
    }
    throw e;
  }
  return candidate.replace(/\/+$/, "");
}

function extractOverallScore(data: any): number {
  return data.security_score ?? data.scores?.overall ?? 0;
}

function buildQuickSummary(data: any, score: number): string {
  if (typeof data.summary === "string" && data.summary.trim()) {
    return data.summary;
  }

  if (data.summary && typeof data.summary === "object") {
    const summary = data.summary;
    const parts = [
      `${summary.total_tests ?? 0} tests run`,
      `${summary.vulnerabilities_found ?? 0} finding(s)`,
    ];

    const severityParts = ["critical", "high", "medium", "low", "info"]
      .filter((severity) => typeof summary[severity] === "number" && summary[severity] > 0)
      .map((severity) => `${summary[severity]} ${severity}`);

    if (severityParts.length > 0) {
      parts.push(severityParts.join(", "));
    }

    return `Quick scan complete: ${parts.join(" | ")}. Overall score ${score}/100.`;
  }

  return `Security score is ${score}/100.`;
}

function extractQuickWins(data: any): string[] {
  if (Array.isArray(data.quick_wins) && data.quick_wins.length > 0) {
    return data.quick_wins.filter((value: unknown): value is string => typeof value === "string");
  }

  if (!Array.isArray(data.vulnerabilities)) {
    return [];
  }

  const recommendations: string[] = [...new Set<string>(
    data.vulnerabilities
      .filter((finding: any) => !finding.passed && typeof finding.recommendation === "string")
      .map((finding: any) => finding.recommendation.trim())
      .filter((value: string) => value.length > 0)
  )];

  return recommendations.slice(0, 3);
}

type NormalizedFinding = {
  severity: string;
  title: string;
  description: string;
  cwe?: string;
  recommendation: string;
};

function normalizeWebsiteFindings(data: any): NormalizedFinding[] {
  if (!Array.isArray(data.vulnerabilities)) {
    return [];
  }

  return data.vulnerabilities
    .filter((finding: any) => !finding.passed)
    .map((finding: any) => ({
      severity: finding.severity || "medium",
      title: finding.testId || "Unknown Issue",
      description: finding.details || finding.message || "",
      cwe: finding.cwe,
      recommendation: finding.recommendation || "Review the finding and apply appropriate fixes.",
    }));
}

function normalizeRepositoryFindings(data: any): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];

  if (Array.isArray(data.security_findings)) {
    findings.push(
      ...data.security_findings
        .filter((finding: any) => finding.passed !== true)
        .map((finding: any) => ({
          severity: finding.severity || "medium",
          title: finding.testId || finding.title || finding.message || "Repository Finding",
          description: finding.details || finding.message || "",
          cwe: Array.isArray(finding.cve) ? finding.cve[0] : finding.cve,
          recommendation: finding.recommendation || "Review the finding and apply appropriate fixes.",
        }))
    );
  }

  if (Array.isArray(data.dependency_vulnerabilities)) {
    findings.push(
      ...data.dependency_vulnerabilities.map((finding: any) => ({
        severity: finding.severity || "medium",
        title: finding.package_name
          ? `Dependency vulnerability: ${finding.package_name}@${finding.current_version || "unknown"}`
          : "Dependency vulnerability",
        description: finding.remediation || finding.description || "A vulnerable dependency was detected.",
        cwe: Array.isArray(finding.cve_ids) ? finding.cve_ids[0] : undefined,
        recommendation: finding.remediation || "Upgrade or replace the affected dependency.",
      }))
    );
  }

  if (Array.isArray(data.trust_posture_findings)) {
    findings.push(
      ...data.trust_posture_findings.map((finding: any) => ({
        severity: finding.severity || "medium",
        title: finding.title || finding.type || "Trust posture issue",
        description: finding.message || finding.details || "",
        recommendation: finding.remediation || finding.recommendation || "Review the repository trust posture finding.",
      }))
    );
  }

  if (Array.isArray(data.behavioral_findings)) {
    findings.push(
      ...data.behavioral_findings.map((finding: any) => ({
        severity: finding.severity || "medium",
        title: finding.title || finding.type || "Suspicious behavior",
        description: finding.message || finding.details || "",
        recommendation: finding.remediation || finding.recommendation || "Review the suspicious behavior finding.",
      }))
    );
  }

  if (Array.isArray(data.malicious_package_findings)) {
    findings.push(
      ...data.malicious_package_findings.map((finding: any) => ({
        severity: finding.severity || "high",
        title: finding.title || finding.package_name || "Malicious package finding",
        description: finding.message || finding.details || "",
        recommendation: finding.remediation || finding.recommendation || "Remove or replace the flagged package.",
      }))
    );
  }

  if (Array.isArray(data.artifact_findings)) {
    findings.push(
      ...data.artifact_findings.map((finding: any) => ({
        severity: finding.severity || "medium",
        title: finding.title || finding.type || "Artifact risk finding",
        description: finding.message || finding.details || "",
        recommendation: finding.remediation || finding.recommendation || "Review the flagged artifact.",
      }))
    );
  }

  return findings;
}

function extractScanFindings(data: any): NormalizedFinding[] {
  if (Array.isArray(data.vulnerabilities)) {
    return normalizeWebsiteFindings(data);
  }

  return normalizeRepositoryFindings(data);
}

export class CyberLensClient {
  private apiKey: string;
  private apiBase: string;
  private timeout: number;

  constructor(apiKey: string, options?: { apiBase?: string; timeout?: number }) {
    this.apiKey = apiKey;
    this.apiBase = resolveApiBase(options?.apiBase);
    this.timeout = options?.timeout ?? 120_000;
  }

  private async request(method: string, path: string, body?: unknown): Promise<any> {
    const url = `${this.apiBase}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        method,
        headers: {
          "X-API-Key": this.apiKey,
          "Content-Type": "application/json",
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (!response.ok) {
        const text = await response.text().catch(() => "");
        let message = `CyberLens API error (${response.status})`;
        let parsed: any;
        try {
          parsed = JSON.parse(text);
          if (parsed.error?.message) message = parsed.error.message;
          else if (typeof parsed.error === "string") message = parsed.error;
        } catch {
          if (text) message = text;
        }

        if (response.status === 402 && parsed?.error?.code === "QUOTA_EXCEEDED") {
          throw new CyberLensQuotaExceededError(message, {
            upgrade_url: parsed.error.upgrade_url,
            quota_type: parsed.error.quota_type,
            used: parsed.error.used,
            limit: parsed.error.limit,
          });
        }

        throw new Error(message);
      }

      return response.json();
    } finally {
      clearTimeout(timer);
    }
  }

  // ---- Scan operations ----

  async startScan(body: Record<string, unknown>): Promise<string> {
    const result = await this.request("POST", "/scan", body);
    return result.data.scan_id;
  }

  async pollScan(scanId: string): Promise<any> {
    let delay = 1000;
    const maxDelay = 30_000;
    let elapsed = 0;

    while (elapsed < this.timeout) {
      await new Promise((r) => setTimeout(r, delay));
      elapsed += delay;

      const result = await this.request("GET", `/scan/${scanId}`);
      const data = result.data;

      if (data.status === "completed") return data;
      if (data.status === "failed") throw new Error("Scan failed on the server.");

      delay = Math.min(delay * 2, maxDelay);
    }

    throw new Error("Scan timed out waiting for results.");
  }

  async scanWebsite(args: ScanWebsiteArgs): Promise<{
    scan_id: string;
    url: string;
    status: string;
    estimated_duration: string;
  }> {
    const scanId = await this.startScan({
      url: args.url,
      scan_type: args.scan_type,
      database_connection: args.database_connection,
    });

    return {
      scan_id: scanId,
      url: args.url,
      status: "pending",
      estimated_duration: args.scan_type === "quick" ? "30 seconds" : "2-3 minutes",
    };
  }

  async scanRepository(args: ScanRepositoryArgs): Promise<{
    scan_id: string;
    url: string;
    status: string;
    estimated_duration: string;
  }> {
    const scanId = await this.startScan({
      repo_url: args.repository_url,
      target_type: "repository",
      depth: args.depth,
      branch: args.branch,
    });

    return {
      scan_id: scanId,
      url: args.repository_url,
      status: "pending",
      estimated_duration: args.depth === "deep" ? "2-3 minutes" : "30-60 seconds",
    };
  }

  async getScanResults(
    scanId: string,
    severityFilter: string = "all"
  ): Promise<{
    scan_id: string;
    url: string;
    status: string;
    security_score: number;
    findings: Array<{
      severity: string;
      title: string;
      description: string;
      cwe?: string;
      recommendation: string;
    }>;
    is_claw_skill?: boolean;
  }> {
    const result = await this.request("GET", `/scan/${scanId}`);
    const data = result.data;

    const isClawSkill =
      data.target_type === "claw_skill" ||
      data.repository_provider === "zip" ||
      data.url?.includes("convex.site") ||
      data.url?.includes("clawhub.ai") ||
      data.website_url?.includes("convex.site") ||
      data.website_url?.includes("clawhub.ai");

    let findings = extractScanFindings(data);

    if (severityFilter !== "all") {
      const severityOrder = ["critical", "high", "medium", "low", "info"];
      const minSeverityIndex = severityOrder.indexOf(severityFilter);
      findings = findings.filter(
        (finding) => severityOrder.indexOf(finding.severity) <= minSeverityIndex
      );
    }

    return {
      scan_id: scanId,
      url: data.url || data.website_url || data.repository_url,
      status: data.scan_status || data.status,
      security_score: extractOverallScore(data),
      findings,
      is_claw_skill: isClawSkill,
    };
  }

  async getSecurityScore(url: string): Promise<{
    url: string;
    score: number;
    grade: string;
    summary: string;
    quick_wins: string[];
  }> {
    const result = await this.request("POST", "/scan", { url, scan_type: "quick" });
    const scanId = result.data.scan_id;
    const data = await this.pollScan(scanId);

    const score = extractOverallScore(data);
    const grade =
      score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";

    return {
      url,
      score,
      grade,
      summary: buildQuickSummary(data, score),
      quick_wins: extractQuickWins(data),
    };
  }

  async getQuota(): Promise<{
    plan: string;
    scans_used: number;
    scans_limit: number;
    scans_remaining: number;
    website_scans_used?: number;
    website_scans_limit?: number;
    website_scans_remaining?: number;
    repo_scans_used?: number;
    repo_scans_limit?: number;
    repo_scans_remaining?: number;
    legacy_combined?: boolean;
    upgrade_recommended?: boolean;
    upgrade_url?: string;
    website_upgrade_required?: boolean;
    website_upgrade_url?: string;
    repo_upgrade_required?: boolean;
    repo_upgrade_url?: string;
  }> {
    const result = await this.request("GET", "/quota");
    return {
      plan: result.data.plan || "unknown",
      scans_used: result.data.scans_used || 0,
      scans_limit: result.data.scans_limit || 0,
      scans_remaining: result.data.scans_remaining || 0,
      website_scans_used: result.data.website_scans_used,
      website_scans_limit: result.data.website_scans_limit,
      website_scans_remaining: result.data.website_scans_remaining,
      repo_scans_used: result.data.repo_scans_used,
      repo_scans_limit: result.data.repo_scans_limit,
      repo_scans_remaining: result.data.repo_scans_remaining,
      legacy_combined: result.data.legacy_combined,
      upgrade_recommended: result.data.upgrade_recommended,
      upgrade_url: result.data.upgrade_url,
      website_upgrade_required: result.data.website_upgrade_required,
      website_upgrade_url: result.data.website_upgrade_url,
      repo_upgrade_required: result.data.repo_upgrade_required,
      repo_upgrade_url: result.data.repo_upgrade_url,
    };
  }
}
