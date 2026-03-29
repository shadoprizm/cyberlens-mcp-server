# Cyber Lens AI MCP Server

> **Security scanning for AI assistants and agentic coding workflows.**

[![MCP](https://img.shields.io/badge/MCP-Compatible-purple)](https://modelcontextprotocol.io)
[![Open CLAW](https://img.shields.io/badge/Open%20CLAW-Native%20Support-blue)](https://openclaw.ai)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933)](https://nodejs.org)

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that gives AI assistants the ability to scan websites, public repositories, and [Open CLAW](https://openclaw.ai) skills for security vulnerabilities. It's purpose-built for the agentic coding era, with native support for scanning skill packages before you install them.

---

## What It Does

When connected to an AI assistant (Claude Desktop, VS Code, etc.), this MCP server adds security scanning tools that the assistant can use during your conversation:

- **Scan a CLAW skill** before installing it -- the server downloads the skill package, extracts it, and analyses the actual source code for dangerous patterns, hardcoded secrets, and permission issues
- **Scan a website** in a local quick mode without an account, or use the full cloud scan when connected
- **Scan a public repository** for exposed secrets, dependency vulnerabilities, suspicious code patterns, and trust posture issues
- **Check your remaining cloud scan quota** before kicking off a batch of scans
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

After the first npm release, the recommended install path is:

```bash
npx -y @cyberlens/mcp-server
```

Before that, or for local development and manual builds:

```bash
git clone https://github.com/shadoprizm/cyberlens-mcp-server.git
cd cyberlens-mcp-server
npm install
npm run build
```

### 2. Add to Your AI Assistant

**Claude Desktop** -- add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "cyberlens": {
      "command": "npx",
      "args": ["-y", "@cyberlens/mcp-server"]
    }
  }
}
```

If you are running from a source checkout instead of npm:

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

Website tools work immediately without an account in local quick mode. That local mode covers roughly 15 core checks and returns results right away.

Connecting an account upgrades website scans to the full CyberLens cloud path with 70+ checks, scan history, and AI analysis. Repository and account-only tools still connect through the browser flow when needed.

When a repository or account-only tool needs an account, the MCP server:

1. opens the CyberLens browser flow automatically
2. sends the user to `cyberlensai.com` to sign up or log in
3. receives the secure callback locally
4. saves the API key to `~/.cyberlens/mcp/config.json`
5. continues the original tool call automatically

You can also trigger the same flow explicitly:

```
You: "Connect my CyberLens account"
```

This opens your browser to [cyberlensai.com](https://cyberlensai.com) where you can sign up (free) or log in. Your API key is saved locally at `~/.cyberlens/mcp/config.json` and used for all future scans.

**Free accounts** include 5 scans/month. No credit card required.

> You can also set the `CYBERLENS_API_KEY` environment variable in the MCP config instead of using the browser flow.

If a cloud website scan hits its monthly quota, the MCP server opens the CyberLens pricing page automatically and falls back to the local quick scan instead of hard-failing. Repository scans still require cloud quota.

---

## Available Tools

### Account

| Tool | Description | Requires API Key |
|------|-------------|:---:|
| `connect_account` | Opens browser to sign up/log in and saves your API key locally | No |
| `get_account_quota` | Shows your current plan and remaining website/repository scan quota; auto-connects on first use if needed | Yes |

### CLAW Skill Scanning

| Tool | Description | Requires API Key |
|------|-------------|:---:|
| `scan_claw_skill` | Download and analyse a CLAW Hub or direct skill package for security issues | No |
| `validate_claw_skill` | Validate a skill manifest against security best practices | No |

### Website & Repository Scanning

| Tool | Description | Requires API Key |
|------|-------------|:---:|
| `scan_website` | Local quick website scan without an account; full cloud scan when connected; local fallback if website cloud quota is exhausted | No for local, Yes for full cloud |
| `scan_repository` | Public repository security scan for GitHub, GitLab, Bitbucket, and supported ZIP targets; auto-connects on first use if needed | Yes |
| `get_scan_results` | Retrieve detailed findings from a completed cloud scan; auto-connects on first use if needed | Yes |
| `get_security_score` | Local quick website score without an account; full cloud score when connected | No for local, Yes for full cloud |

### Intelligence & Guidance

| Tool | Description | Requires API Key |
|------|-------------|:---:|
| `get_remediation_guide` | Built-in local remediation playbooks for common CWEs and vulnerability classes | No |
| `get_scan_transparency` | Honest report of the MCP server's local checks and live cloud endpoints | No |

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

## Website Scan Modes

`scan_website` and `get_security_score` now have two honest modes:

- **Local Quick Scan** -- works without an account, returns immediately, and covers roughly 15 core website checks such as HTTPS, security headers, server disclosure, insecure forms, and inline-script indicators
- **Full Cloud Scan** -- requires a connected CyberLens account, runs 70+ checks, keeps cloud scan history, and includes richer analysis

If a user asks for a `full` or `database` website scan without an account, the MCP server still returns the local quick scan and says that the requested cloud-only mode was not available.

If a connected user runs out of website cloud quota, CyberLens falls back to the local quick scan automatically and opens the pricing page with an upgrade link.

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
  client.ts         REST API client for live scan and quota endpoints
  remediation-guides.ts  Local CWE and vulnerability remediation guidance
  schemas.ts        Zod input validation schemas
  skill-scanner.ts  Local CLAW skill analyser (download, extract, scan)
  skill-validation.ts    Local CLAW manifest validation
  transparency.ts        Local transparency report for scan coverage
```

**Key design decisions:**

- **No Supabase SDK** -- pure REST calls with `fetch` and `X-API-Key` header
- **Truthful cloud surface** -- the MCP server only exposes cloud-backed tools that are supported by the live public API (`/scan`, `/scan/{id}`, `/quota`)
- **Stdio transport** -- runs as a subprocess of the AI assistant, communicates via stdin/stdout
- **Useful without API key** -- skill scanning, website quick scans, manifest validation, remediation guidance, and transparency reporting work locally; connecting an account upgrades website scans to the full cloud path and unlocks repository scanning
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

## Publishing

This repository is prepared for npm + MCP Registry publication as:

- npm package: `@cyberlens/mcp-server`
- MCP server name: `io.github.shadoprizm/cyberlens-mcp-server`

Typical release flow:

```bash
# 1. Bump the version
npm version patch

# 2. Publish the package to npm
npm publish

# 3. Authenticate with the MCP Registry
mcp-publisher login github

# 4. Publish server.json to the MCP Registry
mcp-publisher publish
```

The registry metadata lives in the root `server.json` file and the npm ownership check uses the `mcpName` field in `package.json`.

---

## Related Projects

- **[CyberLens OpenClaw Skill](https://clawhub.ai/shadoprizm/cyberlens)** -- the OpenClaw skill version with the same scanning capabilities
- **[CyberLens](https://cyberlensai.com)** -- the full platform with browser-based scanning, dashboards, and reporting
- **[OpenClaw](https://openclaw.ai)** -- the open skill ecosystem for AI agents

---

## License

[MIT](LICENSE)
