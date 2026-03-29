export interface SkillValidationResult {
  valid: boolean;
  issues: Array<{ severity: string; message: string }>;
  recommendations: string[];
}

const DANGEROUS_PERMISSIONS = [
  "fs:write",
  "fs:delete",
  "network:all",
  "exec:shell",
  "env:all",
  "env:write",
];

export function validateClawSkillManifest(
  manifestJson: string,
  skillCode?: string
): SkillValidationResult {
  const issues: Array<{ severity: string; message: string }> = [];
  const recommendations: string[] = [];

  try {
    const manifest = JSON.parse(manifestJson);

    if (!manifest.name) {
      issues.push({ severity: "error", message: "Missing required field: name" });
    }
    if (!manifest.version) {
      issues.push({ severity: "warning", message: "Missing recommended field: version" });
    }
    if (!manifest.description) {
      issues.push({ severity: "warning", message: "Missing recommended field: description" });
    }

    if (Array.isArray(manifest.permissions)) {
      manifest.permissions.forEach((perm: string) => {
        if (DANGEROUS_PERMISSIONS.some((pattern) => perm.includes(pattern))) {
          issues.push({
            severity: "warning",
            message: `Potentially dangerous permission requested: ${perm}. Ensure this is necessary.`,
          });
        }
      });

      if (manifest.permissions.length > 5) {
        recommendations.push("Consider reducing permission scope - only request what's absolutely necessary");
      }
    }

    if (Array.isArray(manifest.external_apis)) {
      manifest.external_apis.forEach((api: string) => {
        if (!api.startsWith("https://")) {
          issues.push({
            severity: "error",
            message: `External API must use HTTPS: ${api}`,
          });
        }
      });
    }

    if (skillCode) {
      const dangerousPatterns = [
        { pattern: /eval\s*\(/, name: "eval()" },
        { pattern: /child_process/, name: "child_process" },
        { pattern: /fs\.unlink|fs\.rmdir|fs\.rm/, name: "file deletion" },
        { pattern: /fetch\s*\(\s*["']http:\/\//, name: "insecure HTTP request" },
      ];

      dangerousPatterns.forEach(({ pattern, name }) => {
        if (pattern.test(skillCode)) {
          issues.push({
            severity: "warning",
            message: `Potentially dangerous pattern found: ${name}`,
          });
        }
      });
    }
  } catch {
    issues.push({ severity: "error", message: "Invalid JSON in manifest" });
  }

  return {
    valid: issues.filter((issue) => issue.severity === "error").length === 0,
    issues,
    recommendations,
  };
}
