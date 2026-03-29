/**
 * Cyber Lens AI API Client
 * REST API client using X-API-Key authentication.
 * Matches the CyberLens skill's api_client.py pattern.
 */

import { ScanClawSkillArgs, ScanWebsiteArgs, ScanRepositoryArgs, ListCVEAlertsArgs } from "./schemas.js";

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

  async scanClawSkill(args: ScanClawSkillArgs): Promise<{
    scan_id: string;
    skill_name: string;
    url: string;
    status: string;
    estimated_duration: string;
    is_clawhub_certification: boolean;
  }> {
    const skillName = this.extractSkillName(args.skill_url);
    const scanId = await this.startScan({
      url: args.skill_url,
    });

    const durationMap: Record<string, string> = {
      quick: "30 seconds",
      standard: "2 minutes",
      deep: "5 minutes",
      clawhub_certification: "10 minutes (full audit)",
    };

    return {
      scan_id: scanId,
      skill_name: skillName,
      url: args.skill_url,
      status: "pending",
      estimated_duration: durationMap[args.scan_mode] || "2 minutes",
      is_clawhub_certification: args.scan_mode === "clawhub_certification",
    };
  }

  async scanWebsite(args: ScanWebsiteArgs): Promise<{
    scan_id: string;
    url: string;
    status: string;
    estimated_duration: string;
  }> {
    const scanId = await this.startScan({
      url: args.url,
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
          description: v.message || "",
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
      url: data.website_url || data.repository_url,
      status: data.scan_status || data.status,
      security_score: data.security_score || 0,
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

    const score = data.security_score || 0;
    const grade =
      score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";

    return {
      url,
      score,
      grade,
      summary: data.summary || `Security score is ${score}/100`,
      quick_wins: data.quick_wins || [],
    };
  }

  async getQuota(): Promise<any> {
    const result = await this.request("GET", "/quota");
    return result.data;
  }

  async listCVEAlerts(args: ListCVEAlertsArgs): Promise<{
    cves: Array<{
      cve_id: string;
      severity: string;
      cvss_score: number;
      description: string;
      affected: string;
      published: string;
    }>;
  }> {
    const params: Record<string, string> = { days: String(args.days) };
    if (args.technology) params.technology = args.technology;
    if (args.severity !== "all") params.severity = args.severity;

    const query = new URLSearchParams(params).toString();
    const result = await this.request("GET", `/cve?${query}`);
    const cves = result.data || [];

    return {
      cves: cves.map((cve: any) => ({
        cve_id: cve.cve_id,
        severity: cve.severity,
        cvss_score: cve.cvss_score || 0,
        description: cve.description,
        affected: cve.affected_packages || "Unknown",
        published: cve.published_date,
      })),
    };
  }

  async getRemediationGuide(
    cweId: string,
    context?: string
  ): Promise<{
    cwe_id: string;
    title: string;
    description: string;
    steps: string[];
    code_example?: { before: string; after: string };
    prevention: string[];
  }> {
    const params: Record<string, string> = { cwe_id: cweId };
    if (context) params.context = context;

    const query = new URLSearchParams(params).toString();
    const result = await this.request("GET", `/remediation?${query}`);
    const data = result.data;

    if (!data) {
      const isClawContext = context?.toLowerCase().includes("claw");
      return {
        cwe_id: cweId,
        title: `Guidance for ${cweId}`,
        description: `Security guidance for ${cweId}.${isClawContext ? " This is particularly important for CLAW skills that may process untrusted input." : ""}`,
        steps: [
          "Review the vulnerability details",
          "Identify affected code or configuration",
          "Apply recommended security controls",
          "Test the fix thoroughly",
          "Deploy to production",
        ],
        prevention: [
          "Follow secure coding practices",
          "Regular security training for developers",
          "Implement security review processes",
          ...(isClawContext ? ["Validate all inputs in CLAW skill handlers", "Use minimal permission scopes"] : []),
        ],
      };
    }

    return {
      cwe_id: data.cwe_id || cweId,
      title: data.title,
      description: data.description,
      steps: data.remediation_steps || [],
      code_example: data.code_example,
      prevention: data.prevention_tips || [],
    };
  }

  async getScanTransparency(includeChangelog: boolean): Promise<{
    version: string;
    last_updated: string;
    test_count: number;
    categories: Array<{ name: string; count: number }>;
    claw_specific_tests?: number;
    recent_changes?: Array<{
      date: string;
      description: string;
      cve_source?: string;
    }>;
  }> {
    const params = new URLSearchParams({
      include_changelog: String(includeChangelog),
    });
    const result = await this.request("GET", `/transparency?${params.toString()}`);
    const data = result.data;

    return {
      version: data.version || "unknown",
      last_updated: data.last_updated || new Date().toISOString(),
      test_count: data.test_count || 0,
      categories: data.categories || [],
      claw_specific_tests: data.claw_specific_tests,
      recent_changes: data.recent_changes,
    };
  }

  // ---- Helper ----

  private extractSkillName(url: string): string {
    try {
      const parsed = new URL(url);

      if (parsed.hostname.includes("clawhub.ai")) {
        const parts = parsed.pathname.split("/").filter(Boolean);
        return parts.slice(0, 2).join("/") || "unknown-skill";
      }

      if (parsed.hostname.endsWith(".convex.site")) {
        return parsed.searchParams.get("slug") || "claw-skill";
      }

      const match = parsed.pathname.match(/\/([^/]+)\/([^/]+)/);
      if (match) {
        return `${match[1]}/${match[2].replace(/\.git$/, "")}`;
      }

      return "claw-skill";
    } catch {
      return "claw-skill";
    }
  }
}
