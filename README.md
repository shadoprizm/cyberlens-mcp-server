# Cyber Lens AI MCP Server

> **Security scanning for AI assistants and agentic coding workflows.**

[![MCP](https://img.shields.io/badge/MCP-Compatible-purple)](https://modelcontextprotocol.io)
[![Open CLAW](https://img.shields.io/badge/Open%20CLAW-Native%20Support-blue)](https://openclaw.ai)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933)](https://nodejs.org)

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that gives AI assistants the ability to scan code, websites, and repositories for security vulnerabilities. It's purpose-built for the agentic coding era, with native support for scanning [Open CLAW](https://openclaw.ai) skills before you install them.

---

## What It Does

When connected to an AI assistant (Claude Desktop, VS Code, etc.), this MCP server adds security scanning tools that the assistant can use during your conversation:

- **Scan a CLAW skill** before installing it -- the server downloads the skill package, extracts it, and analyses the actual source code for dangerous patterns, hardcoded secrets, and permission issues
- **Scan a website** for security headers, SSL issues, XSS vulnerabilities, and misconfigurations
- **Audit a repository** on GitHub, GitLab, or Bitbucket for secrets, vulnerable dependencies, and insecure code
- **Check CVE alerts** relevant to your tech stack
- **Get remediation guidance** with step-by-step fix instructions and code examples

### Example Conversation

```
You:    "I want to install this skill: https://clawhub.ai/skills/ontology"

Claude: I'll scan it for security issues first.

        [PASS] CLAW Skill Security Scan: ontology v1.0.4

        Security Score: 95/100
        Files Analyzed: 5

        Skill appears safe to install. Minor issues noted below.

        1. [MEDIUM] File write operation
           File: scripts/ontology.py:399
           Fix: Ensure file writes are limited to expected directories.

        The skill looks safe. It writes to the filesystem for its knowledge
        graph storage, which is expected behaviour for this type of skill.
```

---

## Getting Started

### 1. Install

```bash
git clone https://github.com/shadoprizm/cyberlens-mcp-server.git
cd cyberlens-mcp-server
npm install
```

### 2. Add to Your AI Assistant

**Claude Desktop** -- add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "cyberlens": {
      "command": "node",
      "args": ["/absolute/path/to/cyberlens-mcp-server/dist/index.js"]
    }
  }
}
```

**Claude Code** -- add to your MCP settings or project configuration.

**VS Code (Copilot/Continue)** -- configure per your extension's MCP server settings.

### 3. Connect Your Account

On first use, ask your AI assistant to connect your CyberLens account:

```
You: "Connect my CyberLens account"
```

This opens your browser to [cyberlensai.com](https://cyberlensai.com) where you can sign up (free) or log in. Your API key is saved locally at `~/.cyberlens/mcp/config.json` and used for all future scans.

**Free accounts** include 5 scans/month (2 website + 3 repo/skill). No credit card required.

> You can also set the `CYBERLENS_API_KEY` environment variable in the MCP config instead of using the browser flow.

---

## Available Tools

### Account

| Tool | Description | Requires API Key |
|------|-------------|:---:|
| `connect_account` | Opens browser to sign up/log in and saves your API key locally | No |

### CLAW Skill Scanning

| Tool | Description | Requires API Key |
|------|-------------|:---:|
| `scan_claw_skill` | Download and analyse a CLAW skill for security issues | No |
| `validate_claw_skill` | Validate a skill manifest against security best practices | No |

### Website & Repository Scanning

| Tool | Description | Requires API Key |
|------|-------------|:---:|
| `scan_website` | Comprehensive website security scan | Yes |
| `scan_repository` | GitHub/GitLab/Bitbucket repository audit | Yes |
| `get_scan_results` | Retrieve detailed findings from a completed scan | Yes |
| `get_security_score` | Quick security rating (A-F grade) | Yes |

### Intelligence & Guidance

| Tool | Description | Requires API Key |
|------|-------------|:---:|
| `list_cve_alerts` | Recent CVE alerts filtered by technology and severity | Yes |
| `get_remediation_guide` | Step-by-step fix instructions for a CWE or vulnerability | Yes |
| `get_scan_transparency` | What tests the scanner runs and recent changes | Yes |

---

## How Skill Scanning Works

When you provide a CLAW skill URL, the MCP server:

1. **Resolves the URL** -- accepts Claw Hub pages (`https://clawhub.ai/skills/skill-name`), direct download links (`https://*.convex.site/api/v1/download?slug=name`), or any URL pointing to a skill zip
2. **Downloads the skill package** to a temporary directory
3. **Extracts and analyses** every file in the package:
   - Checks `_meta.json` and `SKILL.md` for completeness
   - Scans all source code (Python, JavaScript, TypeScript, shell scripts, config files) for dangerous patterns
   - Detects hardcoded secrets, `eval()` usage, shell command execution, insecure HTTP requests, file deletion operations, pickle deserialisation, and more
   - Identifies unpinned dependencies
   - Catalogues all external URLs the skill communicates with
4. **Returns a security score** (0-100) with detailed findings, file locations, and fix recommendations
5. **Cleans up** all temporary files

This entire process runs locally -- no API key is required and your code is never sent to an external server.

### Accepted URL Formats

```
https://clawhub.ai/skills/ontology            --> Resolves automatically
https://clawhub.ai/author/skill-name          --> Resolves automatically
https://*.convex.site/api/v1/download?slug=x  --> Direct download
```

---

## Architecture

```
src/
  index.ts          MCP server, tool handlers, output formatting
  auth.ts           Browser-based connect flow, config file management
  client.ts         REST API client (X-API-Key auth, fetch-based)
  schemas.ts        Zod input validation schemas
  skill-scanner.ts  Local CLAW skill analyser (download, extract, scan)
```

**Key design decisions:**

- **No Supabase SDK** -- pure REST calls with `fetch` and `X-API-Key` header
- **Stdio transport** -- runs as a subprocess of the AI assistant, communicates via stdin/stdout
- **Graceful without API key** -- skill scanning and manifest validation work locally; cloud features prompt you to connect
- **Browser-based auth** -- same secure connect flow as the CyberLens OpenClaw skill (CSRF-protected, short-lived exchange codes, HTTPS-only)

---

## Development

```bash
# Build
npm run build

# Watch mode
npm run dev

# Run directly (for testing)
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}' | node dist/index.js
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|:---:|---------|-------------|
| `CYBERLENS_API_KEY` | No | -- | API key (alternative to browser connect flow) |
| `CYBERLENS_API_BASE_URL` | No | `https://api.cyberlensai.com/functions/v1/public-api-scan` | API endpoint override |

---

## Related Projects

- **[CyberLens OpenClaw Skill](https://clawhub.ai/shadoprizm/cyberlens)** -- the OpenClaw skill version with the same scanning capabilities
- **[CyberLens](https://cyberlensai.com)** -- the full platform with browser-based scanning, dashboards, and reporting
- **[OpenClaw](https://openclaw.ai)** -- the open skill ecosystem for AI agents

---

## License

[MIT](LICENSE)
