import { z } from "zod";

// Input validation schemas for all MCP tools
// Including EXCLUSIVE Open CLAW skill scanning

export const scanClawSkillSchema = z.object({
  skill_url: z.string().url().describe("CLAUDE Hub skill URL, GitHub repo, or skill download link"),
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
  repository_url: z.string().url().describe("The repository URL to scan"),
  depth: z.enum(["surface", "deep"]).optional().default("surface"),
  branch: z.string().optional().describe("Optional branch name to scan"),
});

export const getScanResultsSchema = z.object({
  scan_id: z.string().uuid().describe("The scan ID returned from scan initiation"),
  severity_filter: z.enum(["all", "critical", "high", "medium", "low", "info"]).optional().default("all"),
});

export const getSecurityScoreSchema = z.object({
  url: z.string().url().describe("The website URL to check"),
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
export type GetRemediationGuideArgs = z.infer<typeof getRemediationGuideSchema>;
