import assert from "node:assert/strict";
import test from "node:test";
import { buildConnectUrl } from "./auth.js";

test("MCP account connections identify themselves as the MCP client", () => {
  const connectUrl = new URL(
    buildConnectUrl("http://localhost:43123/callback", "test-state"),
  );

  assert.equal(connectUrl.origin, "https://cyberlensai.com");
  assert.equal(connectUrl.pathname, "/connect");
  assert.equal(connectUrl.searchParams.get("client"), "cyberlens_mcp");
  assert.equal(connectUrl.searchParams.get("callback"), "http://localhost:43123/callback");
  assert.equal(connectUrl.searchParams.get("state"), "test-state");
});
