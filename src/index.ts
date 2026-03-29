#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { CyberLensClient } from "./client.js";
import { loadApiKey, loadApiBaseUrl, runConnectFlow } from "./auth.js";
import { scanClawSkill as localScanClawSkill, SkillScanResult } from "./skill-scanner.js";
import { getLocalRemediationGuide } from "./remediation-guides.js";
import { validateClawSkillManifest } from "./skill-validation.js";
import { getLocalTransparencyReport } from "./transparency.js";
import {
  ScanWebsiteArgs,
  ScanRepositoryArgs,
  ScanClawSkillArgs,
  GetScanResultsArgs,
  GetSecurityScoreArgs,
  GetRemediationGuideArgs,
  scanWebsiteSchema,
  scanRepositorySchema,
  scanClawSkillSchema,
  getScanResultsSchema,
  getSecurityScoreSchema,
  getRemediationGuideSchema,
} from "./schemas.js";

// Cyber Lens AI MCP Server
// Security scanning for AI assistants and agentic coding workflows
// With native support for Open CLAW skills and CLAUDE Hub

const SERVER_NAME = "cyberlens-security";
const SERVER_VERSION = "1.0.0";

function getClient(): CyberLensClient {
  const apiKey = loadApiKey();
  if (!apiKey) {
    throw new Error(
      "No CyberLens API key found. Use the connect_account tool to link your CyberLens account, " +
        "or set the CYBERLENS_API_KEY environment variable."
    );
  }
  return new CyberLensClient(apiKey, { apiBase: loadApiBaseUrl() || undefined });
}

// Define available tools
const TOOLS: Tool[] = [
  {
    name: "connect_account",
    description: `Connect your CyberLens account to this MCP server.

Opens your browser to cyberlensai.com where you can sign up for free or log in.
After authorizing, your API key is securely saved locally.

Free accounts get 5 scans/month. No credit card required.

Use this tool first before running any scans. If you already have an API key,
you can also set the CYBERLENS_API_KEY environment variable instead.`,
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "get_account_quota",
    description: `Get your CyberLens account quota and remaining cloud scans.

Returns:
- Current plan name
- Total scans used, limit, and remaining
- Website scan usage
- Repository or skill scan usage

Use this to confirm your account is connected and check how many cloud scans remain.`,
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "scan_claw_skill",
    description: `Scan an Open CLAW skill or plugin from CLAUDE Hub before installation.

Runs locally in the MCP server and understands CLAW skill packaging,
manifest permissions, and AI agent security models.

Performs comprehensive security analysis on:
- CLAUDE Hub skill/plugin download links
- Skill manifest files
- Embedded code and dependencies

Checks for:
- Hardcoded secrets and API keys in skill code
- Vulnerable npm/pip dependencies
- Insecure file operations
- Suspicious network requests
- Unsafe eval() or code injection patterns
- Privilege escalation risks
- Data exfiltration patterns
- Permission scope appropriateness

Use this BEFORE installing any CLAW skill to ensure it's safe for your environment.

Examples:
- CLAUDE Hub URL: https://clawhub.ai/username/skill-name
- Plugin download: https://*.convex.site/api/v1/download?slug=skill-name`,
    inputSchema: {
      type: "object",
      properties: {
        skill_url: {
          type: "string",
          description: "CLAUDE Hub skill URL or direct skill download link",
        },
      },
      required: ["skill_url"],
    },
  },
  {
    name: "scan_website",
    description: `Scan a website for security vulnerabilities using Cyber Lens AI.

Performs comprehensive security testing including:
- SSL/TLS certificate validation
- Security headers analysis (CSP, HSTS, X-Frame-Options, etc.)
- XSS and injection vulnerability checks
- Third-party script integrity verification
- Account-specific scan features supported by the live CyberLens API

Returns a scan ID that can be used with get_scan_results to retrieve findings.
Optional scan profile fields are forwarded to the live CyberLens API when supported.`,
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "The website URL to scan (e.g., https://example.com)",
        },
        scan_type: {
          type: "string",
          enum: ["quick", "full", "database"],
          description: "Type of scan: quick (basic checks), full (comprehensive), or database (includes DB security)",
          default: "full",
        },
        database_connection: {
          type: "object",
          description: "Optional database connection for database security scanning",
          properties: {
            provider: {
              type: "string",
              enum: ["postgres", "supabase"],
            },
            connection_string: {
              type: "string",
              description: "Database connection string (password will be encrypted)",
            },
          },
        },
      },
      required: ["url"],
    },
  },
  {
    name: "scan_repository",
    description: `Scan a GitHub, GitLab, or Bitbucket repository for security issues.

Checks for:
- Hardcoded secrets and API keys
- Vulnerable dependencies
- Insecure code patterns
- Misconfigurations in CI/CD files
- Dockerfile and docker-compose security

Ideal for auditing code before deployment or evaluating third-party dependencies.
The repository URL is required. Additional fields like branch and depth are forwarded
to the live CyberLens API when supported.`,
    inputSchema: {
      type: "object",
      properties: {
        repo_url: {
          type: "string",
          description: "Repository URL (e.g., https://github.com/owner/repo)",
        },
        branch: {
          type: "string",
          description: "Branch to scan (default: main)",
          default: "main",
        },
        depth: {
          type: "string",
          enum: ["surface", "deep"],
          description: "Scan depth: surface (quick) or deep (comprehensive)",
          default: "surface",
        },
      },
      required: ["repo_url"],
    },
  },
  {
    name: "get_scan_results",
    description: `Retrieve detailed findings from a completed security scan.

Returns:
- Overall security score (0-100)
- List of vulnerabilities with severity levels
- CWE classifications
- Specific recommendations for each finding
- CVE references where applicable
- Remediation guidance links

Use this after initiating a cloud scan with scan_website or scan_repository.`,
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID returned from scan initiation",
        },
        severity_filter: {
          type: "string",
          enum: ["all", "critical", "high", "medium", "low", "info"],
          description: "Filter results by severity level",
          default: "all",
        },
      },
      required: ["scan_id"],
    },
  },
  {
    name: "get_security_score",
    description: `Get a quick security rating for a website without running a full scan.

Returns:
- Overall security score (0-100)
- Grade (A-F)
- Key metrics summary
- Quick wins for improvement

Use this for a fast assessment when full vulnerability details aren't needed.`,
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "The website URL to check",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "get_remediation_guide",
    description: `Get detailed remediation guidance for a specific vulnerability or CWE.

Returns:
- Explanation of the vulnerability
- Step-by-step fix instructions
- Code examples (before/after)
- Testing procedures
- Prevention strategies

Uses a built-in local guide library, so it still works even when no cloud guidance endpoint is available.`,
    inputSchema: {
      type: "object",
      properties: {
        cwe_id: {
          type: "string",
          description: "CWE ID (e.g., 'CWE-79', 'CWE-89') or vulnerability name",
        },
        context: {
          type: "string",
          description: "Additional context about your stack (e.g., 'react', 'express', 'django', 'claw-skill')",
        },
      },
      required: ["cwe_id"],
    },
  },
  {
    name: "get_scan_transparency",
    description: `Get an honest transparency report for this MCP server.

Returns:
- Current MCP server version
- Local check inventory and category counts
- Which live cloud API endpoints this server actually uses
- Recent changes to the MCP scan surface

Use this to understand exactly what this server checks locally and which cloud features are live.`,
    inputSchema: {
      type: "object",
      properties: {
        include_changelog: {
          type: "boolean",
          description: "Include recent changes to the scanner",
          default: true,
        },
      },
    },
  },
  {
    name: "validate_claw_skill",
    description: `Validate a CLAW skill manifest and configuration for security best practices.

Checks:
- Skill manifest.json structure and required fields
- Permission scopes (are they minimal?)
- External API dependencies
- File system access patterns
- Environment variable usage
- Plugin isolation safety

Use this before publishing a skill to CLAUDE Hub or for CI/CD validation.`,
    inputSchema: {
      type: "object",
      properties: {
        manifest_json: {
          type: "string",
          description: "The skill's manifest.json content as a string",
        },
        skill_code: {
          type: "string",
          description: "Optional: main skill code for deeper analysis",
        },
      },
      required: ["manifest_json"],
    },
  },
];

// Create MCP server
const server = new Server(
  {
    name: SERVER_NAME,
    version: SERVER_VERSION,
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Handle tool list requests
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools: TOOLS };
});

// Handle tool execution
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "connect_account": {
        const result = await runConnectFlow();
        return {
          content: [
            {
              type: "text",
              text: formatConnectSuccess(result.config_path),
            },
          ],
        };
      }

      case "get_account_quota": {
        const client = getClient();
        const result = await client.getQuota();
        return {
          content: [
            {
              type: "text",
              text: formatAccountQuota(result),
            },
          ],
        };
      }

      case "scan_claw_skill": {
        const parsed = scanClawSkillSchema.parse(args);
        const result = await localScanClawSkill(parsed.skill_url);
        return {
          content: [
            {
              type: "text",
              text: formatSkillScanResults(result),
            },
          ],
        };
      }

      case "scan_website": {
        const client = getClient();
        const parsed = scanWebsiteSchema.parse(args);
        const result = await client.scanWebsite(parsed);
        return {
          content: [
            {
              type: "text",
              text: formatScanInitiated(result),
            },
          ],
        };
      }

      case "scan_repository": {
        const client = getClient();
        const parsed = scanRepositorySchema.parse(args);
        const result = await client.scanRepository(parsed);
        return {
          content: [
            {
              type: "text",
              text: formatScanInitiated(result),
            },
          ],
        };
      }

      case "get_scan_results": {
        const client = getClient();
        const parsed = getScanResultsSchema.parse(args);
        const result = await client.getScanResults(parsed.scan_id, parsed.severity_filter);
        return {
          content: [
            {
              type: "text",
              text: formatScanResults(result),
            },
          ],
        };
      }

      case "get_security_score": {
        const client = getClient();
        const parsed = getSecurityScoreSchema.parse(args);
        const result = await client.getSecurityScore(parsed.url);
        return {
          content: [
            {
              type: "text",
              text: formatSecurityScore(result),
            },
          ],
        };
      }

      case "get_remediation_guide": {
        const parsed = getRemediationGuideSchema.parse(args);
        const result = getLocalRemediationGuide(parsed.cwe_id, parsed.context);
        return {
          content: [
            {
              type: "text",
              text: formatRemediationGuide(result),
            },
          ],
        };
      }

      case "get_scan_transparency": {
        const parsed = args as { include_changelog?: boolean };
        const result = getLocalTransparencyReport({
          version: SERVER_VERSION,
          includeChangelog: parsed.include_changelog ?? true,
        });
        return {
          content: [
            {
              type: "text",
              text: formatTransparencyReport(result),
            },
          ],
        };
      }

      case "validate_claw_skill": {
        const { manifest_json, skill_code } = args as { manifest_json: string; skill_code?: string };
        const result = validateClawSkillManifest(manifest_json, skill_code);
        return {
          content: [
            {
              type: "text",
              text: formatSkillValidation(result),
            },
          ],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: "text",
          text: `Error: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
});

// Formatting functions

function formatSkillScanResults(result: SkillScanResult): string {
  const scoreLabel = result.security_score >= 80 ? "PASS" : result.security_score >= 60 ? "WARN" : "FAIL";

  let output = `[${scoreLabel}] CLAW Skill Security Scan: ${result.skill_name} v${result.version}

Security Score: ${result.security_score}/100
Files Analyzed: ${result.files_analyzed}

${result.summary}

`;

  if (result.findings.length === 0) {
    output += "No issues found. Skill looks clean.\n";
  } else {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = [...result.findings].sort(
      (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
    );

    // Group by severity for summary
    const counts: Record<string, number> = {};
    for (const f of sorted) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    }
    const countParts = Object.entries(counts)
      .sort(([a], [b]) => severityOrder[a as keyof typeof severityOrder] - severityOrder[b as keyof typeof severityOrder])
      .map(([sev, n]) => `${n} ${sev}`);
    output += `Findings: ${countParts.join(", ")}\n\n`;

    sorted.forEach((finding, i) => {
      output += `${i + 1}. [${finding.severity.toUpperCase()}] ${finding.title}\n`;
      output += `   ${finding.description}\n`;
      if (finding.file) {
        output += `   File: ${finding.file}${finding.line ? `:${finding.line}` : ""}\n`;
      }
      output += `   Fix: ${finding.recommendation}\n\n`;
    });
  }

  return output;
}

function formatConnectSuccess(configPath: string): string {
  return `Connected to CyberLens AI successfully!

Your API key has been saved to: ${configPath}

You can now use all scanning tools:
  - get_account_quota: Check your plan and remaining scans
  - scan_website: Scan a website for security issues
  - scan_repository: Audit a GitHub/GitLab/Bitbucket repo
  - scan_claw_skill: Scan a CLAW skill before installing
  - get_security_score: Quick security rating
  - validate_claw_skill: Validate a skill manifest locally

Free accounts include 5 scans/month.`;
}

function formatScanInitiated(result: { scan_id: string; url: string; status: string; estimated_duration: string }): string {
  return `Security Scan Initiated

Target: ${result.url}
Scan ID: ${result.scan_id}
Status: ${result.status}
Estimated Duration: ${result.estimated_duration}

The scan is now running. Use get_scan_results with the scan_id to check progress and retrieve findings.`;
}

function formatScanResults(result: {
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
}): string {
  const scoreLabel = result.security_score >= 80 ? "PASS" : result.security_score >= 60 ? "WARN" : "FAIL";
  const clawBadge = result.is_claw_skill ? "\nCLAW Skill Scan Results\n" : "";
  const normalizedStatus = result.status.toLowerCase();

  let output = `[${scoreLabel}] Security Scan Results for ${result.url}${clawBadge}

Security Score: ${result.security_score}/100
Status: ${result.status}
Scan ID: ${result.scan_id}

`;

  if (normalizedStatus !== "completed") {
    if (normalizedStatus === "failed") {
      output += "The scan did not complete successfully. Review the target and try again.\n";
    } else {
      output += `The scan is still ${result.status}. Run get_scan_results again in a moment for the final findings.\n`;
    }
    return output;
  }

  if (result.findings.length === 0) {
    output += "No vulnerabilities found!\n";
    if (result.is_claw_skill) {
      output += "\nThis CLAW skill appears safe to install based on the scan.\n";
    }
  } else {
    output += `Found ${result.findings.length} issue(s):\n\n`;

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = [...result.findings].sort(
      (a, b) =>
        (severityOrder[a.severity as keyof typeof severityOrder] ?? 5) -
        (severityOrder[b.severity as keyof typeof severityOrder] ?? 5)
    );

    sorted.forEach((finding, index) => {
      output += `${index + 1}. [${finding.severity.toUpperCase()}] ${finding.title}\n`;
      output += `   ${finding.description}\n`;
      if (finding.cwe) {
        output += `   CWE: ${finding.cwe}\n`;
      }
      output += `   Fix: ${finding.recommendation}\n\n`;
    });

    if (result.is_claw_skill) {
      const criticalCount = result.findings.filter((f) => f.severity === "critical").length;
      if (criticalCount > 0) {
        output += "\nWarning: Critical issues found. Review carefully before installing this CLAW skill.\n";
      }
    }
  }

  return output;
}

function formatSecurityScore(result: {
  url: string;
  score: number;
  grade: string;
  summary: string;
  quick_wins: string[];
}): string {
  let output = `Quick Security Assessment for ${result.url}

Score: ${result.score}/100
Grade: ${result.grade}

${result.summary}

`;

  if (result.quick_wins.length > 0) {
    output += "Quick Wins:\n";
    result.quick_wins.forEach((win, i) => {
      output += `  ${i + 1}. ${win}\n`;
    });
  }

  return output;
}

function formatAccountQuota(result: {
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
}): string {
  let output = `CyberLens Account Quota\n\n`;
  output += `Plan: ${result.plan}\n`;
  output += `Total Scans: ${result.scans_used}/${result.scans_limit} used (${result.scans_remaining} remaining)\n`;

  if (typeof result.website_scans_limit === "number") {
    output += `Website Scans: ${result.website_scans_used}/${result.website_scans_limit} used (${result.website_scans_remaining} remaining)\n`;
  }

  if (typeof result.repo_scans_limit === "number") {
    output += `Repository or Skill Scans: ${result.repo_scans_used}/${result.repo_scans_limit} used (${result.repo_scans_remaining} remaining)\n`;
  }

  if (typeof result.legacy_combined === "boolean") {
    output += `Legacy Combined Quota: ${result.legacy_combined ? "Yes" : "No"}\n`;
  }

  return output;
}

function formatRemediationGuide(result: {
  cwe_id: string;
  title: string;
  description: string;
  steps: string[];
  code_example?: { before: string; after: string };
  prevention: string[];
}): string {
  let output = `Remediation Guide: ${result.title}\n`;
  output += `CWE: ${result.cwe_id}\n\n`;
  output += `${result.description}\n\n`;

  output += "Step-by-Step Fix:\n";
  result.steps.forEach((step, i) => {
    output += `  ${i + 1}. ${step}\n`;
  });

  if (result.code_example) {
    output += "\nCode Example:\n\n";
    output += "Before:\n";
    output += "```\n" + result.code_example.before + "\n```\n\n";
    output += "After:\n";
    output += "```\n" + result.code_example.after + "\n```\n";
  }

  output += "\nPrevention Strategies:\n";
  result.prevention.forEach((strategy, i) => {
    output += `  ${i + 1}. ${strategy}\n`;
  });

  return output;
}

function formatTransparencyReport(result: {
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
  cloud_endpoints: string[];
  notes: string[];
}): string {
  let output = `Cyber Lens AI Scanner Transparency Report\n\n`;
  output += `Version: ${result.version}\n`;
  output += `Last Updated: ${result.last_updated}\n`;
  output += `Total Tests: ${result.test_count}\n\n`;

  output += "Test Categories:\n";
  result.categories.forEach((cat) => {
    output += `  - ${cat.name}: ${cat.count} tests\n`;
  });

  if (result.claw_specific_tests) {
    output += `\nCLAW-Specific Checks: ${result.claw_specific_tests}\n`;
  }

  output += "\nLive Cloud Endpoints Used:\n";
  result.cloud_endpoints.forEach((endpoint) => {
    output += `  - ${endpoint}\n`;
  });

  output += "\nNotes:\n";
  result.notes.forEach((note) => {
    output += `  - ${note}\n`;
  });

  if (result.recent_changes && result.recent_changes.length > 0) {
    output += "\nRecent Changes:\n";
    result.recent_changes.slice(0, 10).forEach((change) => {
      output += `  [${change.date}] ${change.description}`;
      if (change.cve_source) {
        output += ` (Source: ${change.cve_source})`;
      }
      output += "\n";
    });
  }

  return output;
}

function formatSkillValidation(result: {
  valid: boolean;
  issues: Array<{ severity: string; message: string }>;
  recommendations: string[];
}): string {
  const statusLabel = result.valid ? "PASS" : "FAIL";

  let output = `[${statusLabel}] CLAW Skill Validation Results\n\n`;

  if (result.issues.length === 0) {
    output += "No issues found! Skill manifest looks good.\n";
  } else {
    output += `Found ${result.issues.length} issue(s):\n\n`;

    result.issues.forEach((issue) => {
      const label = issue.severity === "error" ? "ERROR" : "WARN";
      output += `[${label}] ${issue.message}\n`;
    });
  }

  if (result.recommendations.length > 0) {
    output += "\nRecommendations:\n";
    result.recommendations.forEach((rec, i) => {
      output += `  ${i + 1}. ${rec}\n`;
    });
  }

  return output;
}

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Cyber Lens AI MCP Server running on stdio");

  const hasKey = !!loadApiKey();
  if (hasKey) {
    console.error("API key loaded - ready to scan");
  } else {
    console.error("No API key found - use connect_account tool to get started");
  }
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
