import assert from "node:assert/strict";
import test from "node:test";
import { getLocalTransparencyReport } from "./transparency.js";

test("transparency report reflects the supported local and cloud scan surface", () => {
  const report = getLocalTransparencyReport({
    version: "1.0.0",
    includeChangelog: true,
  });

  const totalFromCategories = report.categories.reduce((sum, category) => sum + category.count, 0);

  assert.equal(report.test_count, totalFromCategories);
  assert.deepEqual(report.cloud_endpoints, [
    "POST /scan",
    "GET /scan/{scan_id}",
    "GET /quota",
  ]);
  assert.ok(report.notes.length >= 3);
  assert.ok(report.recent_changes && report.recent_changes.length >= 1);
});

test("transparency report can omit the changelog", () => {
  const report = getLocalTransparencyReport({
    version: "1.0.0",
    includeChangelog: false,
  });

  assert.equal(report.recent_changes, undefined);
});
