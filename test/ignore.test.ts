import { test } from "node:test";
import assert from "node:assert/strict";
import { auditCompose } from "../src/audit.ts";
import { parseCompose } from "../src/load.ts";

const rulesFor = (yaml: string, service: string) =>
  auditCompose(parseCompose(yaml))
    .filter((f) => f.service === service)
    .map((f) => f.rule)
    .sort();

const BASE = `services:
  cache:
    image: redis:latest
    ports:
      - "6379:6379"
  other:
    image: redis:latest
    ports:
      - "6380:6379"
`;

test("an ignore comment above a service silences those rules for it only", () => {
  const before = rulesFor(BASE, "cache");
  assert.ok(before.length >= 2, `expected findings, got ${before}`);
  const [first, second] = before;
  const yaml = BASE.replace(
    "  cache:\n",
    `  # homelab-audit: ignore ${first}, ${second}\n  cache:\n`,
  );
  const after = rulesFor(yaml, "cache");
  assert.ok(!after.includes(first) && !after.includes(second), String(after));
  assert.deepEqual(rulesFor(yaml, "other"), rulesFor(BASE, "other"));
});

test("an ignore comment inside the service's block works too", () => {
  const [first] = rulesFor(BASE, "cache");
  const yaml = BASE.replace(
    '    image: redis:latest\n    ports:\n      - "6379:6379"',
    `    image: redis:latest  # homelab-audit: ignore ${first}\n    ports:\n      - "6379:6379"`,
  );
  assert.ok(!rulesFor(yaml, "cache").includes(first));
});

test("a comment that isn't an ignore directive changes nothing", () => {
  const yaml = BASE.replace(
    "  cache:\n",
    "  # cache for the app, ignore it\n  cache:\n",
  );
  assert.deepEqual(rulesFor(yaml, "cache"), rulesFor(BASE, "cache"));
});
