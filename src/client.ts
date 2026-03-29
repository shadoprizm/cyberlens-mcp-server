/**
 * Cyber Lens AI API Client
 * REST API client using X-API-Key authentication.
 * Matches the CyberLens skill's public scan API surface.
 */

import { ScanWebsiteArgs, ScanRepositoryArgs } from "./schemas.js";

const DEFAULT_API_BASE = "https://api.cyberlensai.com/functions/v1/public-api-scan";

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
        try {
          const parsed = JSON.parse(text);
          if (parsed.error?.message) message = parsed.error.message;
          else if (typeof parsed.error === "string") message = parsed.error;
        } catch {
          if (text) message = text;
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
      url: args.repo_url,
      repo_url: args.repo_url,
      branch: args.branch,
      depth: args.depth,
    });

    return {
      scan_id: scanId,
      url: args.repo_url,
      status: "pending",
      estimated_duration: args.depth === "surface" ? "1-2 minutes" : "3-5 minutes",
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

    let findings: Array<{
      severity: string;
      title: string;
      description: string;
      cwe?: string;
      recommendation: string;
    }> = [];

    if (data.vulnerabilities && Array.isArray(data.vulnerabilities)) {
      findings = data.vulnerabilities
        .filter((v: any) => !v.passed)
        .map((v: any) => ({
          severity: v.severity || "medium",
          title: v.testId || "Unknown Issue",
          description: v.details || v.message || "",
          cwe: v.cwe,
          recommendation: v.recommendation || "Review the finding and apply appropriate fixes.",
        }));

      if (severityFilter !== "all") {
        const severityOrder = ["critical", "high", "medium", "low", "info"];
        const minSeverityIndex = severityOrder.indexOf(severityFilter);
        findings = findings.filter(
          (f) => severityOrder.indexOf(f.severity) <= minSeverityIndex
        );
      }
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
    };
  }
}
