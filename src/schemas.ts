import { z } from "zod";

// Input validation schemas for all MCP tools
// Including EXCLUSIVE Open CLAW skill scanning

export const scanClawSkillSchema = z.object({
  skill_url: z.string().url().describe("CLAUDE Hub skill URL, GitHub repo, or skill download link"),
  scan_mode: z.enum(["quick", "standard", "deep", "clawhub_certification"]).optional().default("standard"),
});

export const scanWebsiteSchema = z.object({
  url: z.string().url().describe("The website URL to scan"),
  scan_type: z.enum(["quick", "full", "database"]).optional().default("full"),
  database_connection: z.object({
    provider: z.enum(["postgres", "supabase"]),
    connection_string: z.string(),
  }).optional(),
});

export const scanRepositorySchema = z.object({
  repo_url: z.string().url().describe("Repository URL (GitHub, GitLab, or Bitbucket)"),
  branch: z.string().optional().default("main"),
  depth: z.enum(["surface", "deep"]).optional().default("surface"),
});

export const getScanResultsSchema = z.object({
  scan_id: z.string().uuid().describe("The scan ID returned from scan initiation"),
  severity_filter: z.enum(["all", "critical", "high", "medium", "low", "info"]).optional().default("all"),
});

export const getSecurityScoreSchema = z.object({
  url: z.string().url().describe("The website URL to check"),
});

export const listCVEAlertsSchema = z.object({
  days: z.number().min(1).max(30).optional().default(7),
  technology: z.string().optional(),
  severity: z.enum(["all", "critical", "high", "medium", "low"]).optional().default("all"),
});

export const getRemediationGuideSchema = z.object({
  cwe_id: z.string().describe("CWE ID (e.g., 'CWE-79') or vulnerability name"),
  context: z.string().optional().describe("Additional context about your stack"),
});

// Type exports
export type ScanClawSkillArgs = z.infer<typeof scanClawSkillSchema>;
export type ScanWebsiteArgs = z.infer<typeof scanWebsiteSchema>;
export type ScanRepositoryArgs = z.infer<typeof scanRepositorySchema>;
export type GetScanResultsArgs = z.infer<typeof getScanResultsSchema>;
export type GetSecurityScoreArgs = z.infer<typeof getSecurityScoreSchema>;
export type ListCVEAlertsArgs = z.infer<typeof listCVEAlertsSchema>;
export type GetRemediationGuideArgs = z.infer<typeof getRemediationGuideSchema>;
