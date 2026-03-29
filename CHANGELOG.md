# Changelog

## [1.0.0] - 2026-03-29

### Added
- `connect_account` tool -- browser-based sign up/login flow, saves API key locally
- `scan_claw_skill` tool -- downloads and analyses CLAW skill packages locally
- `scan_website` tool -- website security scanning via CyberLens cloud API
- `scan_repository` tool -- repository audit via CyberLens cloud API
- `get_scan_results` tool -- retrieve detailed scan findings
- `get_security_score` tool -- quick A-F security rating
- `list_cve_alerts` tool -- recent CVE alerts by technology/severity
- `get_remediation_guide` tool -- step-by-step vulnerability fix instructions
- `get_scan_transparency` tool -- scanner test inventory and changelog
- `validate_claw_skill` tool -- local skill manifest validation
- Automatic Claw Hub URL resolution (fetches page, extracts download link)
- Local skill analysis: dangerous code patterns, hardcoded secrets, manifest checks, dependency auditing
- REST API client with `X-API-Key` authentication (no Supabase SDK)
- Browser-based auth with CSRF protection and secure code exchange
- Config file storage at `~/.cyberlens/mcp/config.json`
- TypeScript with strict mode, Zod input validation
- MCP stdio transport for AI assistant integration
