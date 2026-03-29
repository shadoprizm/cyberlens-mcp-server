import assert from "node:assert/strict";
import test from "node:test";
import { validateClawSkillManifest } from "./skill-validation.js";

test("flags dangerous permissions in skill manifests", () => {
  const result = validateClawSkillManifest(
    JSON.stringify({
      name: "demo",
      version: "1.0.0",
      description: "demo skill",
      permissions: ["fs:write", "network:all"],
    })
  );

  assert.equal(result.valid, true);
  assert.ok(result.issues.some((issue) => issue.message.includes("fs:write")));
  assert.ok(result.issues.some((issue) => issue.message.includes("network:all")));
});

test("rejects invalid manifest JSON", () => {
  const result = validateClawSkillManifest("{not-json");

  assert.equal(result.valid, false);
  assert.deepEqual(result.issues, [
    { severity: "error", message: "Invalid JSON in manifest" },
  ]);
});
