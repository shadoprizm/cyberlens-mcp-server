export interface RemediationGuideResult {
  cwe_id: string;
  title: string;
  description: string;
  steps: string[];
  code_example?: { before: string; after: string };
  prevention: string[];
}

interface GuideTemplate extends RemediationGuideResult {
  aliases: string[];
}

const GUIDE_LIBRARY: GuideTemplate[] = [
  {
    cwe_id: "CWE-79",
    aliases: ["XSS", "CROSS SITE SCRIPTING", "CROSS-SITE SCRIPTING"],
    title: "Cross-Site Scripting (XSS)",
    description:
      "Untrusted input is rendered into HTML or script contexts without proper output encoding. Attackers can execute JavaScript in another user's browser, steal sessions, or alter page behavior.",
    steps: [
      "Trace every place the untrusted value enters the response.",
      "Apply context-appropriate output encoding before rendering HTML, attributes, URLs, or JavaScript.",
      "Use framework-safe templating or component escaping instead of string concatenation.",
      "Sanitize rich HTML with a vetted allowlist sanitizer if raw markup must be supported.",
      "Retest reflected, stored, and DOM-based entry points after the fix.",
    ],
    code_example: {
      before: "res.send(`<div>${userInput}</div>`);",
      after: "res.send(`<div>${escapeHtml(userInput)}</div>`);",
    },
    prevention: [
      "Default to auto-escaping templates and JSX.",
      "Reject raw HTML insertion unless the source is trusted and sanitized.",
      "Enable a Content Security Policy to reduce exploit impact.",
    ],
  },
  {
    cwe_id: "CWE-89",
    aliases: ["SQL INJECTION", "SQLI"],
    title: "SQL Injection",
    description:
      "User-controlled data is being composed into SQL queries. Attackers can read, modify, or destroy database data and sometimes escalate to broader system compromise.",
    steps: [
      "Identify the query path where untrusted input reaches SQL construction.",
      "Replace string interpolation with parameterized queries or a query builder.",
      "Validate input shape and type before it reaches the data layer.",
      "Limit database permissions for the application account.",
      "Retest read, write, search, and filter endpoints with malicious payloads.",
    ],
    code_example: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`);",
      after: "db.query('SELECT * FROM users WHERE email = $1', [email]);",
    },
    prevention: [
      "Use prepared statements everywhere, including admin scripts and migrations.",
      "Never trust ORM escape hatches that allow raw SQL without parameters.",
      "Log and review rejected payloads to spot probing patterns.",
    ],
  },
  {
    cwe_id: "CWE-78",
    aliases: ["COMMAND INJECTION", "OS COMMAND INJECTION"],
    title: "OS Command Injection",
    description:
      "Untrusted input is reaching shell or process execution APIs. An attacker may be able to run arbitrary operating system commands on the host.",
    steps: [
      "Find where untrusted values are passed into shell commands or process arguments.",
      "Remove shell invocation when possible and call the underlying library or binary directly.",
      "If a process call is unavoidable, pass arguments as a fixed array and validate each input.",
      "Run the process with the minimum privileges and isolated working directories.",
      "Retest with metacharacters, separators, and path traversal payloads.",
    ],
    code_example: {
      before: "exec(`grep ${userInput} ./data.txt`);",
      after: "spawn('grep', ['--', userInput, './data.txt']);",
    },
    prevention: [
      "Avoid `exec`, `system`, and shell=True style APIs for user-facing paths.",
      "Constrain command execution behind explicit allowlists.",
      "Record and review all privileged subprocess usage.",
    ],
  },
  {
    cwe_id: "CWE-22",
    aliases: ["PATH TRAVERSAL", "DIRECTORY TRAVERSAL"],
    title: "Path Traversal",
    description:
      "Untrusted input is influencing filesystem paths without normalization and confinement checks. Attackers may read or overwrite files outside the intended workspace.",
    steps: [
      "Normalize the requested path before use.",
      "Resolve it against a fixed base directory and reject paths that escape that root.",
      "Separate user identifiers from actual filenames where possible.",
      "Apply least-privilege filesystem permissions to the runtime account.",
      "Retest with `..`, encoded separators, symlinks, and absolute path payloads.",
    ],
    code_example: {
      before: "const fullPath = path.join(baseDir, userPath);",
      after: "const fullPath = path.resolve(baseDir, userPath); if (!fullPath.startsWith(path.resolve(baseDir) + path.sep)) throw new Error('invalid path');",
    },
    prevention: [
      "Use generated identifiers instead of raw user filenames when possible.",
      "Never trust client-provided relative paths without resolution and prefix checks.",
      "Review symlink handling for upload and extraction flows.",
    ],
  },
  {
    cwe_id: "CWE-502",
    aliases: ["INSECURE DESERIALIZATION", "DESERIALIZATION"],
    title: "Deserialization of Untrusted Data",
    description:
      "The application is decoding or deserializing data in a format that can execute code or instantiate unsafe objects. Attackers may achieve remote code execution or logic abuse.",
    steps: [
      "Identify every place untrusted bytes or strings are deserialized.",
      "Replace unsafe formats such as pickle or native object serialization with safer formats like JSON.",
      "If complex types are required, validate against an explicit schema before use.",
      "Treat signed or internal-only payloads separately from public input.",
      "Retest with malformed and crafted serialized objects.",
    ],
    code_example: {
      before: "const value = pickle.loads(payload);",
      after: "const value = JSON.parse(payload); validateSchema(value);",
    },
    prevention: [
      "Avoid language-native deserialization formats for untrusted input.",
      "Require explicit schema validation after parsing.",
      "Separate transport parsing from object construction.",
    ],
  },
];

function normalizeIdentifier(value: string): string {
  return value.trim().toUpperCase().replace(/[\s_-]+/g, " ");
}

function cloneGuide(guide: RemediationGuideResult): RemediationGuideResult {
  return {
    ...guide,
    steps: [...guide.steps],
    prevention: [...guide.prevention],
    code_example: guide.code_example ? { ...guide.code_example } : undefined,
  };
}

function buildGenericGuide(input: string, context?: string): RemediationGuideResult {
  const normalizedContext = context?.trim();
  const clawContext = normalizedContext?.toLowerCase().includes("claw");

  return {
    cwe_id: input.toUpperCase(),
    title: `Guidance for ${input.toUpperCase()}`,
    description:
      `Security guidance for ${input}. Review how untrusted input, secrets, filesystem access, and network access are handled in the affected code path.` +
      (clawContext ? " Pay extra attention to permission scope and host-side effects in CLAW skills." : ""),
    steps: [
      "Identify the exact code path and trust boundary involved in the finding.",
      "Remove unsafe defaults and validate input before it reaches sensitive operations.",
      "Apply the narrowest possible permissions, data access, and side effects for the feature.",
      "Add regression tests that cover both expected and malicious inputs.",
      "Re-run the relevant security scan after patching.",
    ],
    prevention: [
      "Prefer safe platform APIs over custom parsing or shell execution.",
      "Document the intended trust model for the feature.",
      "Add security review checks to PRs for code paths that touch secrets, filesystem access, or network calls.",
      ...(clawContext
        ? [
            "Keep CLAW skill permissions minimal and documented.",
            "Constrain file writes and external network calls to clearly justified destinations.",
          ]
        : []),
    ],
  };
}

export function getLocalRemediationGuide(cweIdOrName: string, context?: string): RemediationGuideResult {
  const normalized = normalizeIdentifier(cweIdOrName);
  const guide = GUIDE_LIBRARY.find((entry) => {
    const keys = [entry.cwe_id, ...entry.aliases].map(normalizeIdentifier);
    return keys.includes(normalized);
  });

  const result = guide ? cloneGuide(guide) : buildGenericGuide(cweIdOrName, context);
  const clawContext = context?.toLowerCase().includes("claw");

  if (clawContext) {
    result.steps.push("Verify the skill's declared permissions, filesystem scope, and outbound network destinations are still justified after the fix.");
    result.prevention.push("Review whether the skill can achieve the same outcome with fewer permissions.");
  }

  return result;
}
