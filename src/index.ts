#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { buildUpgradeUrl, loadApiKey, openUpgradePage, runConnectFlow } from "./auth.js";
import { getCloudClient, getExistingCloudClient } from "./cloud-client.js";
import { CyberLensQuotaExceededError } from "./client.js";
import { scanClawSkill as localScanClawSkill, SkillScanResult } from "./skill-scanner.js";
import { getLocalRemediationGuide } from "./remediation-guides.js";
import { validateClawSkillManifest } from "./skill-validation.js";
import { getLocalTransparencyReport } from "./transparency.js";
import { LocalWebsiteScanResult, scanWebsiteLocally } from "./website-scanner.js";
import {
  scanRepositorySchema,
  scanWebsiteSchema,
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

// Define available tools
const TOOLS: Tool[] = [
  {
    name: "connect_account",
    description: `Connect your CyberLens account to this MCP server.

Opens your browser to cyberlensai.com where you can sign up for free or log in.
After authorizing, your API key is securely saved locally.

Free accounts get 5 scans/month. No credit card required.

If you already have an API key, you can also set the CYBERLENS_API_KEY
environment variable instead. Cloud tools can also launch this flow
automatically the first time repository or account-only tools need an account.`,
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

Use this to confirm your account is connected and check how many cloud scans remain.
If no account is connected yet, the MCP server will launch the CyberLens
browser flow automatically before checking quota.`,
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
    description: `Scan a website for security vulnerabilities with a local quick mode and a full cloud mode.

Without a connected account, the MCP server runs a local quick scan immediately.
That local mode covers roughly 15 core checks such as HTTPS, security headers,
basic form issues, inline scripts, and server disclosure.

With a connected account, CyberLens starts the full cloud scan with 70+ checks.
That path returns a scan ID you can use with get_scan_results.

If cloud website quota is exhausted, CyberLens falls back to the local quick scan
automatically and opens the upgrade page.`,
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
          description: "Cloud scan profile. Local mode always uses a quick scan and warns if full or database was requested.",
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
    description: `Scan a public repository for secrets, dependency risks, and suspicious code patterns.

Uses the live CyberLens cloud repository scanner for:
- Public GitHub, GitLab, and Bitbucket repositories
- Supported CLAUDE Hub or direct ZIP download URLs

Checks for:
- Exposed secrets and credentials
- Vulnerable dependencies
- Suspicious or risky code behavior
- Trust posture and repository hygiene signals
- Artifact and package reputation issues

Returns a scan ID that can be used with get_scan_results to retrieve findings.
If no account is connected yet, the MCP server will open the CyberLens
browser flow automatically and then continue the scan.`,
    inputSchema: {
      type: "object",
      properties: {
        repository_url: {
          type: "string",
          description: "The repository URL to scan (for example https://github.com/owner/repo)",
        },
        depth: {
          type: "string",
          enum: ["surface", "deep"],
          description: "Surface is faster. Deep runs a broader repository analysis.",
          default: "surface",
        },
        branch: {
          type: "string",
          description: "Optional branch name to scan. Defaults to the repository's default branch.",
        },
      },
      required: ["repository_url"],
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

Use this after initiating a full cloud scan with scan_website or scan_repository.
Local quick website scans return findings immediately and do not produce a scan ID.
If no account is connected yet, the MCP server will connect first and then
retrieve the cloud scan result.`,
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
    description: `Get a quick security rating for a website.

Returns:
- Overall security score (0-100)
- Grade (A-F)
- Key metrics summary
- Quick wins for improvement

Without an account, this uses the local quick website scanner.
With an account, this uses the full CyberLens cloud path.
If cloud website quota is exhausted, CyberLens falls back to the local quick score automatically.`,
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
        const context = await getCloudClient();
        const client = context.client;
        const result = await client.getQuota();
        return {
          content: [
            {
              type: "text",
              text: withAutoConnectNotice(formatAccountQuota(result), context),
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
        const parsed = scanWebsiteSchema.parse(args);

        const existingContext = getExistingCloudClient();
        if (!existingContext) {
          const localResult = await scanWebsiteLocally(parsed.url, {
            requestedScanType: parsed.scan_type,
            databaseConnectionProvided: !!parsed.database_connection,
          });
          return {
            content: [
              {
                type: "text",
                text: formatLocalWebsiteScan(localResult, "no_account"),
              },
            ],
            isError: !!localResult.error,
          };
        }

        const client = existingContext.client;
        try {
          const result = await client.scanWebsite(parsed);
          return {
            content: [
              {
                type: "text",
                text: formatScanInitiated(result),
              },
            ],
          };
        } catch (error) {
          if (error instanceof CyberLensQuotaExceededError) {
            const upgradeUrl = error.upgrade_url || buildUpgradeUrl(error.quota_type || "website");
            openUpgradePage(upgradeUrl);
            const localResult = await scanWebsiteLocally(parsed.url, {
              requestedScanType: parsed.scan_type,
              databaseConnectionProvided: !!parsed.database_connection,
            });
            return {
              content: [
                {
                  type: "text",
                  text: formatLocalWebsiteScan(localResult, "quota_exhausted", error, upgradeUrl),
                },
              ],
              isError: !!localResult.error,
            };
          }
          throw error;
        }
      }

      case "scan_repository": {
        const context = await getCloudClient();
        const client = context.client;
        const parsed = scanRepositorySchema.parse(args);
        const result = await client.scanRepository(parsed);
        return {
          content: [
            {
              type: "text",
              text: withAutoConnectNotice(formatScanInitiated(result), context),
            },
          ],
        };
      }

      case "get_scan_results": {
        const context = await getCloudClient();
        const client = context.client;
        const parsed = getScanResultsSchema.parse(args);
        const result = await client.getScanResults(parsed.scan_id, parsed.severity_filter);
        return {
          content: [
            {
              type: "text",
              text: withAutoConnectNotice(formatScanResults(result), context),
            },
          ],
        };
      }

      case "get_security_score": {
        const parsed = getSecurityScoreSchema.parse(args);
        const existingContext = getExistingCloudClient();
        if (!existingContext) {
          const localResult = await scanWebsiteLocally(parsed.url, {
            requestedScanType: "quick",
          });
          return {
            content: [
              {
                type: "text",
                text: formatLocalSecurityScore(localResult, "no_account"),
              },
            ],
            isError: !!localResult.error,
          };
        }

        const client = existingContext.client;
        try {
          const result = await client.getSecurityScore(parsed.url);
          return {
            content: [
              {
                type: "text",
                text: formatSecurityScore(result),
              },
            ],
          };
        } catch (error) {
          if (error instanceof CyberLensQuotaExceededError) {
            const upgradeUrl = error.upgrade_url || buildUpgradeUrl(error.quota_type || "website");
            openUpgradePage(upgradeUrl);
            const localResult = await scanWebsiteLocally(parsed.url, {
              requestedScanType: "quick",
            });
            return {
              content: [
                {
                  type: "text",
                  text: formatLocalSecurityScore(localResult, "quota_exhausted", error, upgradeUrl),
                },
              ],
              isError: !!localResult.error,
            };
          }
          throw error;
        }
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
    if (error instanceof CyberLensQuotaExceededError) {
      const upgradeUrl = error.upgrade_url || buildUpgradeUrl(error.quota_type || "combined");
      openUpgradePage(upgradeUrl);
      return {
        content: [
          {
            type: "text",
            text: formatQuotaUpgradePrompt(error, upgradeUrl),
          },
        ],
        isError: true,
      };
    }

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
  - scan_website: Upgrade website scans from the local quick mode to the full cloud scan
  - scan_repository: Scan a public repository for security issues
  - scan_claw_skill: Scan a CLAW skill before installing
  - get_security_score: Upgrade quick website scores to the full cloud score flow
  - validate_claw_skill: Validate a skill manifest locally

Free accounts include 5 scans/month.`;
}

function withAutoConnectNotice(
  text: string,
  context: { connected_now: boolean; config_path?: string }
): string {
  if (!context.connected_now) {
    return text;
  }

  const configLine = context.config_path
    ? `API key saved to: ${context.config_path}`
    : "API key saved locally for future scans.";

  return `Connected to CyberLens AI automatically.
${configLine}

${text}`;
}

function formatScanInitiated(result: { scan_id: string; url: string; status: string; estimated_duration: string }): string {
  return `Full Cloud Scan Initiated

Target: ${result.url}
Mode: Full Cloud Scan (70+ checks)
Scan ID: ${result.scan_id}
Status: ${result.status}
Estimated Duration: ${result.estimated_duration}

The scan is now running. Use get_scan_results with the scan_id to check progress and retrieve findings.`;
}

function formatQuotaUpgradePrompt(
  error: {
    message: string;
    quota_type?: "website" | "repository" | "combined";
    used?: number;
    limit?: number;
  },
  upgradeUrl: string
): string {
  const quotaLabel =
    error.quota_type === "repository"
      ? "repository scans"
      : error.quota_type === "website"
        ? "website scans"
        : "cloud scans";
  const usageLine =
    typeof error.used === "number" && typeof error.limit === "number"
      ? `Usage: ${error.used}/${error.limit}\n`
      : "";

  return `Upgrade Required

${error.message}
${usageLine}CyberLens opened the pricing page in your browser.
If it did not open automatically, use this link:
${upgradeUrl}

Upgrade to continue ${quotaLabel} immediately, or wait until the next monthly reset.`;
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

function formatLocalWebsiteScan(
  result: LocalWebsiteScanResult,
  reason: "no_account" | "quota_exhausted",
  quotaError?: {
    message: string;
    used?: number;
    limit?: number;
  },
  upgradeUrl?: string
): string {
  if (result.error) {
    return `Local Quick Website Scan Failed

Target: ${result.url}
Mode: Local Quick Scan (~15 core checks)
Error: ${result.error}

${result.warnings.join("\n")}`;
  }

  const scoreLabel = result.score >= 80 ? "PASS" : result.score >= 60 ? "WARN" : "FAIL";
  let output = `[${scoreLabel}] Local Quick Website Scan for ${result.url}

Mode: Local Quick Scan (~15 core checks)
Requested Scan Mode: ${result.requested_scan_type}
Effective Scan Mode: ${result.effective_scan_type}
Security Score: ${result.score}/100
Grade: ${result.grade}
Scan Time: ${result.scan_time_ms}ms
`;

  if (reason === "no_account") {
    output += `
No CyberLens account is connected, so this website scan ran locally.
Connect your account to unlock the full cloud scan with 70+ checks, scan history, and AI analysis.
`;
  } else {
    const usageLine =
      typeof quotaError?.used === "number" && typeof quotaError?.limit === "number"
        ? `Cloud website quota: ${quotaError.used}/${quotaError.limit}\n`
        : "";
    output += `
Cloud website quota is exhausted, so CyberLens ran the local quick scan instead.
${usageLine}CyberLens opened the pricing page in your browser.
Upgrade URL: ${upgradeUrl}
`;
  }

  if (result.warnings.length > 0) {
    output += `\nNotes:\n`;
    result.warnings.forEach((warning) => {
      output += `  - ${warning}\n`;
    });
  }

  if (result.technologies.length > 0) {
    output += `\nTechnologies: ${result.technologies.join(", ")}\n`;
  }

  if (result.findings.length === 0) {
    output += `\nNo issues found in the local quick scan.\n`;
    return output;
  }

  output += `\nFound ${result.findings.length} issue(s):\n\n`;
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...result.findings].sort(
    (a, b) =>
      severityOrder[a.severity as keyof typeof severityOrder] -
      severityOrder[b.severity as keyof typeof severityOrder]
  );

  sorted.forEach((finding, index) => {
    output += `${index + 1}. [${finding.severity.toUpperCase()}] ${finding.type}\n`;
    output += `   ${finding.description}\n`;
    if (finding.evidence) {
      output += `   Evidence: ${finding.evidence}\n`;
    }
    output += `   Fix: ${finding.recommendation}\n\n`;
  });

  return output;
}

function formatLocalSecurityScore(
  result: LocalWebsiteScanResult,
  reason: "no_account" | "quota_exhausted",
  quotaError?: {
    message: string;
    used?: number;
    limit?: number;
  },
  upgradeUrl?: string
): string {
  if (result.error) {
    return `Local Quick Security Score Failed

Target: ${result.url}
Mode: Local Quick Scan (~15 core checks)
Error: ${result.error}
`;
  }

  let output = `Quick Security Assessment for ${result.url}

Mode: Local Quick Scan (~15 core checks)
Score: ${result.score}/100
Grade: ${result.grade}
`;

  if (reason === "no_account") {
    output += `
No CyberLens account is connected, so this score came from the local quick website scan.
Connect your account for the full cloud scan with 70+ checks, scan history, and AI analysis.
`;
  } else {
    const usageLine =
      typeof quotaError?.used === "number" && typeof quotaError?.limit === "number"
        ? `Cloud website quota: ${quotaError.used}/${quotaError.limit}\n`
        : "";
    output += `
Cloud website quota is exhausted, so CyberLens generated this score from the local quick scan instead.
${usageLine}CyberLens opened the pricing page in your browser.
Upgrade URL: ${upgradeUrl}
`;
  }

  if (result.warnings.length > 0) {
    output += `\nNotes:\n`;
    result.warnings.forEach((warning) => {
      output += `  - ${warning}\n`;
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
  upgrade_recommended?: boolean;
  upgrade_url?: string;
  website_upgrade_required?: boolean;
  website_upgrade_url?: string;
  repo_upgrade_required?: boolean;
  repo_upgrade_url?: string;
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

  const quotaWarnings: string[] = [];
  if (result.website_upgrade_required) {
    quotaWarnings.push("Website scan quota exhausted");
  }
  if (result.repo_upgrade_required) {
    quotaWarnings.push("Repository scan quota exhausted");
  }

  if (quotaWarnings.length > 0) {
    output += `\nUpgrade Recommended: ${quotaWarnings.join("; ")}\n`;
    output += `Upgrade URL: ${result.upgrade_url || buildUpgradeUrl("combined")}\n`;
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
    console.error("No API key found - website tools will use the local quick scan until you connect a CyberLens account");
  }
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
