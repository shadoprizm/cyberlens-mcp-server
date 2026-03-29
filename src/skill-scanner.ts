/**
 * Local CLAW skill scanner.
 * Downloads a skill zip, extracts it, analyzes the contents, and cleans up.
 */

import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execSync } from "node:child_process";

export interface SkillFinding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  file?: string;
  line?: number;
  recommendation: string;
}

export interface SkillScanResult {
  skill_name: string;
  version: string;
  files_analyzed: number;
  findings: SkillFinding[];
  security_score: number;
  summary: string;
}

// Dangerous code patterns to scan for
const CODE_PATTERNS: Array<{
  pattern: RegExp;
  severity: SkillFinding["severity"];
  title: string;
  description: string;
  recommendation: string;
}> = [
  // Critical
  {
    pattern: /eval\s*\(/g,
    severity: "critical",
    title: "eval() usage detected",
    description: "eval() executes arbitrary code and is a common injection vector.",
    recommendation: "Replace eval() with safer alternatives like JSON.parse() or AST-based evaluation.",
  },
  {
    pattern: /exec\s*\(\s*["'`]|os\.system\s*\(|subprocess\.(call|run|Popen)\s*\(/g,
    severity: "critical",
    title: "Shell command execution",
    description: "Direct shell command execution can lead to command injection.",
    recommendation: "Use parameterized commands and avoid passing user input to shell execution.",
  },
  {
    pattern: /child_process/g,
    severity: "critical",
    title: "child_process module imported",
    description: "child_process allows arbitrary command execution on the host system.",
    recommendation: "Avoid child_process unless absolutely necessary. Document why it's needed.",
  },
  // High
  {
    pattern: /(?:api[_-]?key|secret[_-]?key|password|token|auth)\s*[:=]\s*["'][A-Za-z0-9+/=_-]{16,}["']/gi,
    severity: "high",
    title: "Possible hardcoded secret",
    description: "A string resembling an API key, token, or password is hardcoded in the source.",
    recommendation: "Move secrets to environment variables or a secure vault. Never commit credentials.",
  },
  {
    pattern: /fetch\s*\(\s*["']http:\/\//g,
    severity: "high",
    title: "Insecure HTTP request",
    description: "Plaintext HTTP requests expose data in transit to interception.",
    recommendation: "Use HTTPS for all external requests.",
  },
  {
    pattern: /requests\.get\s*\(\s*["']http:\/\/|httpx\.(get|post)\s*\(\s*["']http:\/\//g,
    severity: "high",
    title: "Insecure HTTP request (Python)",
    description: "Plaintext HTTP requests expose data in transit to interception.",
    recommendation: "Use HTTPS for all external requests.",
  },
  {
    pattern: /fs\.unlink|fs\.rmdir|fs\.rm\b|os\.remove|os\.unlink|shutil\.rmtree/g,
    severity: "high",
    title: "File deletion operation",
    description: "Skill performs file deletion which could damage user data.",
    recommendation: "Ensure file deletion is scoped to the skill's own working directory only.",
  },
  {
    pattern: /\bopen\s*\([^)]*,\s*["']w/g,
    severity: "medium",
    title: "File write operation",
    description: "Skill writes to the filesystem. Verify writes are scoped and intentional.",
    recommendation: "Ensure file writes are limited to expected directories (e.g., memory/, output/).",
  },
  // Medium
  {
    pattern: /import\s+pickle|from\s+pickle\s+import|pickle\.loads?\(/g,
    severity: "medium",
    title: "Pickle deserialization",
    description: "Pickle can execute arbitrary code during deserialization.",
    recommendation: "Use JSON or another safe serialization format instead of pickle.",
  },
  {
    pattern: /import\s+ctypes|from\s+ctypes/g,
    severity: "medium",
    title: "ctypes usage",
    description: "ctypes allows calling C functions and manipulating memory directly.",
    recommendation: "Avoid ctypes unless there's a clear, documented need for native code access.",
  },
  {
    pattern: /process\.env|os\.environ|os\.getenv/g,
    severity: "low",
    title: "Environment variable access",
    description: "Skill reads environment variables, which may contain sensitive data.",
    recommendation: "Document which environment variables the skill needs and why.",
  },
  {
    pattern: /(?:https?:\/\/)[^\s"'`,)}\]]+/g,
    severity: "info",
    title: "External URL reference",
    description: "Skill references an external URL.",
    recommendation: "Review that external URLs are legitimate and necessary.",
  },
];

// Dangerous permission scopes in manifests
const DANGEROUS_PERMISSIONS = [
  { pattern: "fs:write", reason: "Can write arbitrary files" },
  { pattern: "fs:delete", reason: "Can delete files" },
  { pattern: "network:all", reason: "Unrestricted network access" },
  { pattern: "exec:shell", reason: "Can execute shell commands" },
  { pattern: "env:all", reason: "Can read all environment variables" },
  { pattern: "env:write", reason: "Can modify environment variables" },
];

function extractUrls(content: string): string[] {
  const urlRegex = /https?:\/\/[^\s"'`,)}\]>]+/g;
  return [...new Set(content.match(urlRegex) || [])];
}

function analyzeFile(
  filePath: string,
  content: string,
  relativePath: string
): SkillFinding[] {
  const findings: SkillFinding[] = [];

  for (const check of CODE_PATTERNS) {
    // Skip URL extraction for non-code files and the generic URL pattern
    if (check.title === "External URL reference") continue;

    const matches = content.matchAll(check.pattern);
    for (const match of matches) {
      const lineNum = content.substring(0, match.index).split("\n").length;
      findings.push({
        severity: check.severity,
        title: check.title,
        description: check.description,
        file: relativePath,
        line: lineNum,
        recommendation: check.recommendation,
      });
    }
  }

  return findings;
}

function analyzeManifest(
  meta: any,
  skillMd: string | null
): SkillFinding[] {
  const findings: SkillFinding[] = [];

  // Check _meta.json
  if (!meta.slug) {
    findings.push({
      severity: "medium",
      title: "Missing skill slug",
      description: "Skill metadata is missing a slug identifier.",
      recommendation: "Ensure _meta.json includes a slug field.",
    });
  }
  if (!meta.version) {
    findings.push({
      severity: "low",
      title: "Missing version",
      description: "Skill metadata does not specify a version.",
      recommendation: "Include a version field in _meta.json for tracking.",
    });
  }

  // Check SKILL.md frontmatter
  if (skillMd) {
    const frontmatterMatch = skillMd.match(/^---\n([\s\S]*?)\n---/);
    if (!frontmatterMatch) {
      findings.push({
        severity: "medium",
        title: "Missing SKILL.md frontmatter",
        description: "SKILL.md should have YAML frontmatter with name and description.",
        recommendation: "Add frontmatter with at minimum: name, description.",
      });
    } else {
      const fm = frontmatterMatch[1];
      if (!fm.includes("name:")) {
        findings.push({
          severity: "medium",
          title: "Missing skill name in SKILL.md",
          description: "SKILL.md frontmatter should include a name field.",
          recommendation: "Add 'name:' to SKILL.md frontmatter.",
        });
      }
      if (!fm.includes("description:")) {
        findings.push({
          severity: "low",
          title: "Missing description in SKILL.md",
          description: "SKILL.md frontmatter should include a description.",
          recommendation: "Add 'description:' to SKILL.md frontmatter.",
        });
      }
    }
  } else {
    findings.push({
      severity: "medium",
      title: "Missing SKILL.md",
      description: "No SKILL.md found. This file documents the skill's purpose and usage.",
      recommendation: "Add a SKILL.md with frontmatter (name, description) and usage documentation.",
    });
  }

  return findings;
}

function analyzeDependencies(content: string, file: string): SkillFinding[] {
  const findings: SkillFinding[] = [];

  // Check for unpinned dependencies
  const lines = content.split("\n").filter((l) => l.trim() && !l.startsWith("#"));
  for (const line of lines) {
    const trimmed = line.trim();
    if (file.endsWith("requirements.txt")) {
      if (!trimmed.includes("==") && !trimmed.includes(">=") && !trimmed.includes("~=")) {
        findings.push({
          severity: "low",
          title: "Unpinned dependency",
          description: `Dependency "${trimmed}" has no version constraint.`,
          file,
          recommendation: "Pin dependencies to specific versions (e.g., package==1.2.3) for reproducibility.",
        });
      }
    }
  }

  return findings;
}

function collectExternalUrls(files: Map<string, string>): SkillFinding[] {
  const allUrls = new Set<string>();
  for (const [, content] of files) {
    for (const url of extractUrls(content)) {
      allUrls.add(url);
    }
  }

  const findings: SkillFinding[] = [];
  for (const url of allUrls) {
    if (url.startsWith("http://") && !url.startsWith("http://localhost") && !url.startsWith("http://127.0.0.1")) {
      findings.push({
        severity: "medium",
        title: "Insecure HTTP URL referenced",
        description: `The skill references an insecure URL: ${url}`,
        recommendation: "Use HTTPS for all external communications.",
      });
    }
  }

  if (allUrls.size > 0) {
    const httpsList = [...allUrls].filter((u) => u.startsWith("https://"));
    if (httpsList.length > 0) {
      findings.push({
        severity: "info",
        title: "External endpoints",
        description: `Skill communicates with ${httpsList.length} external HTTPS endpoint(s): ${httpsList.slice(0, 5).join(", ")}${httpsList.length > 5 ? ` and ${httpsList.length - 5} more` : ""}`,
        recommendation: "Verify these endpoints are legitimate and necessary for the skill's function.",
      });
    }
  }

  return findings;
}

function calculateScore(findings: SkillFinding[]): number {
  let score = 100;
  for (const f of findings) {
    switch (f.severity) {
      case "critical": score -= 20; break;
      case "high": score -= 10; break;
      case "medium": score -= 5; break;
      case "low": score -= 2; break;
      // info doesn't affect score
    }
  }
  return Math.max(0, score);
}

function walkDir(dir: string, base: string = dir): Map<string, string> {
  const files = new Map<string, string>();
  const entries = execSync(`find "${dir}" -type f`, { encoding: "utf-8" })
    .trim()
    .split("\n")
    .filter(Boolean);

  for (const entry of entries) {
    try {
      const content = readFileSync(entry, "utf-8");
      const relative = entry.replace(base + "/", "");
      files.set(relative, content);
    } catch {
      // Skip binary files that can't be read as utf-8
    }
  }
  return files;
}

const CLAWHUB_HOSTS = new Set([
  "clawhub.ai",
  "www.clawhub.ai",
  "claw-hub.net",
  "openclaw-hub.org",
]);

/**
 * Resolve a skill URL to a direct download URL.
 * - convex.site download links → use as-is
 * - clawhub.ai skill pages → fetch page, extract download link
 * - GitHub/GitLab repos → not supported for local scan (would need cloud API)
 */
async function resolveDownloadUrl(inputUrl: string): Promise<string> {
  const parsed = new URL(inputUrl);

  // Already a direct download link
  if (parsed.hostname.endsWith(".convex.site")) {
    return inputUrl;
  }

  // Claw Hub URL — fetch the page and extract the download link
  if (CLAWHUB_HOSTS.has(parsed.hostname)) {
    const response = await fetch(inputUrl, {
      signal: AbortSignal.timeout(15_000),
      redirect: "follow",
    });
    if (!response.ok) {
      throw new Error(`Failed to fetch Claw Hub page: HTTP ${response.status}`);
    }
    const html = await response.text();

    // Extract the convex.site download URL from the page
    const downloadMatch = html.match(
      /https:\/\/[a-z0-9-]+\.convex\.site\/api\/v1\/download\?[^"'\s<>]+/
    );
    if (!downloadMatch) {
      throw new Error(
        "Could not find a download link on the Claw Hub page. " +
          "The skill may not be published or the page format has changed."
      );
    }
    return downloadMatch[0];
  }

  // GitHub/GitLab — not directly downloadable as a CLAW skill zip
  if (
    parsed.hostname === "github.com" ||
    parsed.hostname === "gitlab.com" ||
    parsed.hostname === "bitbucket.org"
  ) {
    throw new Error(
      "Repository URLs cannot be scanned as CLAW skills directly. " +
        "Use scan_repository for repo security audits, or provide the Claw Hub or download URL."
    );
  }

  // Unknown URL — try fetching it as a zip
  return inputUrl;
}

export async function scanClawSkill(skillUrl: string): Promise<SkillScanResult> {
  const downloadUrl = await resolveDownloadUrl(skillUrl);

  const tempDir = mkdtempSync(join(tmpdir(), "cyberlens-skill-"));
  const zipPath = join(tempDir, "skill.zip");
  const extractDir = join(tempDir, "extracted");

  try {
    // Download
    const response = await fetch(downloadUrl);
    if (!response.ok) {
      throw new Error(`Failed to download skill: HTTP ${response.status}`);
    }
    const buffer = Buffer.from(await response.arrayBuffer());
    const { writeFileSync } = await import("node:fs");
    writeFileSync(zipPath, buffer);

    // Extract
    execSync(`mkdir -p "${extractDir}" && unzip -o "${zipPath}" -d "${extractDir}"`, {
      stdio: "pipe",
    });

    // Read all files
    const files = walkDir(extractDir);

    // Parse metadata
    let meta: any = {};
    const metaContent = files.get("_meta.json");
    if (metaContent) {
      try {
        meta = JSON.parse(metaContent);
      } catch {}
    }

    const skillMd = files.get("SKILL.md") || null;

    // Run all analyses
    const findings: SkillFinding[] = [];

    // Manifest / metadata analysis
    findings.push(...analyzeManifest(meta, skillMd));

    // Code analysis on each file
    const codeExtensions = [".py", ".js", ".ts", ".sh", ".bash", ".yaml", ".yml", ".json", ".toml"];
    let filesAnalyzed = 0;

    for (const [relativePath, content] of files) {
      const isCode = codeExtensions.some((ext) => relativePath.endsWith(ext));
      const isMarkdown = relativePath.endsWith(".md");

      if (isCode) {
        findings.push(...analyzeFile(join(extractDir, relativePath), content, relativePath));
        filesAnalyzed++;
      }

      // Check dependency files
      if (
        relativePath === "requirements.txt" ||
        relativePath.endsWith("/requirements.txt")
      ) {
        findings.push(...analyzeDependencies(content, relativePath));
        filesAnalyzed++;
      }

      // Count markdown as analyzed too
      if (isMarkdown) filesAnalyzed++;
    }

    // External URL analysis across all files
    findings.push(...collectExternalUrls(files));

    const score = calculateScore(findings);
    const skillName = meta.slug || "unknown-skill";
    const version = meta.version || "unknown";

    const critCount = findings.filter((f) => f.severity === "critical").length;
    const highCount = findings.filter((f) => f.severity === "high").length;

    let summary: string;
    if (critCount > 0) {
      summary = `Critical security issues found. Do NOT install this skill without reviewing the ${critCount} critical finding(s).`;
    } else if (highCount > 0) {
      summary = `${highCount} high-severity issue(s) found. Review before installing.`;
    } else if (score >= 80) {
      summary = "Skill appears safe to install. Minor issues noted below.";
    } else {
      summary = "Several issues found. Review findings before installing.";
    }

    return {
      skill_name: skillName,
      version,
      files_analyzed: filesAnalyzed,
      findings,
      security_score: score,
      summary,
    };
  } finally {
    // Always clean up
    rmSync(tempDir, { recursive: true, force: true });
  }
}
