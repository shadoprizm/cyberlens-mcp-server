# Release process

## Automated gate

Run the complete source gate before publishing:

```bash
npm ci
npm run release:check
npm pack --dry-run
```

CI repeats lint, build, tests, and dependency audit on Node 18.20.8 and Node 22. The package job also inspects the npm tarball on Node 22.

## Publish 1.0.1

The release manager must publish from a clean `main` commit that passed CI:

```bash
npm whoami
npm publish --access public
npm view @shadoprizm/cyberlens-mcp-server@1.0.1 version dist.integrity --json
git tag -a v1.0.1 -m "CyberLens MCP Server 1.0.1"
git push origin v1.0.1
```

Do not create or push the tag before npm confirms the immutable public version. npm authentication, 2FA, and the final publish are owner-controlled release actions.
