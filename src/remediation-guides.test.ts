import assert from "node:assert/strict";
import test from "node:test";
import { getLocalRemediationGuide } from "./remediation-guides.js";

test("returns a specific remediation guide for well-known CWE aliases", () => {
  const guide = getLocalRemediationGuide("xss");

  assert.equal(guide.cwe_id, "CWE-79");
  assert.match(guide.title, /Cross-Site Scripting/i);
  assert.ok(guide.steps.length >= 4);
});

test("adds CLAW-specific hardening advice when requested", () => {
  const guide = getLocalRemediationGuide("CWE-78", "claw-skill");

  assert.ok(
    guide.prevention.some((item) => item.includes("permissions")),
    "expected CLAW-specific prevention guidance"
  );
  assert.ok(
    guide.steps.some((step) => step.includes("declared permissions")),
    "expected CLAW-specific remediation step"
  );
});

test("falls back to generic guidance for unknown identifiers", () => {
  const guide = getLocalRemediationGuide("CWE-999");

  assert.equal(guide.cwe_id, "CWE-999");
  assert.match(guide.title, /Guidance for CWE-999/);
  assert.ok(guide.prevention.length >= 3);
});
