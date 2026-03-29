export interface TransparencyReport {
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
}

const LOCAL_CHECK_CATEGORIES = [
  { name: "Code execution and injection", count: 3 },
  { name: "Secrets and credentials", count: 1 },
  { name: "Network and external endpoint hygiene", count: 3 },
  { name: "Filesystem safety", count: 2 },
  { name: "Unsafe runtime behavior", count: 3 },
  { name: "Manifest and documentation checks", count: 6 },
  { name: "Dependency hygiene", count: 1 },
  { name: "Permission scope review", count: 6 },
];

const RECENT_CHANGES = [
  {
    date: "2026-03-29",
    description: "Removed MCP tools that depended on unsupported /cve backend endpoints and replaced them with supported quota reporting.",
  },
  {
    date: "2026-03-29",
    description: "Moved remediation guidance into local, built-in playbooks so the tool works even when no cloud guide endpoint is available.",
  },
  {
    date: "2026-03-29",
    description: "Restored public repository scans after wiring the public API back into the live repository-scanner backend and verified end-to-end repo scan startup.",
  },
  {
    date: "2026-03-29",
    description: "Updated transparency reporting to reflect the actual local checks and live cloud endpoints used by the MCP server.",
  },
];

const CLOUD_ENDPOINTS = [
  "POST /scan",
  "GET /scan/{scan_id}",
  "GET /quota",
];

const NOTES = [
  "CLAW skill scanning and manifest validation run locally in the MCP server and do not require a CyberLens API key.",
  "Website scanning uses the live CyberLens public scan API.",
  "Repository scanning uses the live CyberLens public scan API and routes into the repository-scanner worker.",
  "The MCP server only exposes cloud-backed tools that are currently supported by the live backend.",
];

export function getLocalTransparencyReport(input: {
  version: string;
  includeChangelog: boolean;
}): TransparencyReport {
  return {
    version: input.version,
    last_updated: "2026-03-29",
    test_count: LOCAL_CHECK_CATEGORIES.reduce((sum, category) => sum + category.count, 0),
    categories: LOCAL_CHECK_CATEGORIES.map((category) => ({ ...category })),
    claw_specific_tests: 15,
    recent_changes: input.includeChangelog ? RECENT_CHANGES.map((change) => ({ ...change })) : undefined,
    cloud_endpoints: [...CLOUD_ENDPOINTS],
    notes: [...NOTES],
  };
}
