import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { main, parseFlags } from "../src/cli.ts";

const fixture = (name: string) =>
  fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));

function silent<T>(fn: () => T): T {
  const log = console.log;
  const err = console.error;
  console.log = () => {};
  console.error = () => {};
  try {
    return fn();
  } finally {
    console.log = log;
    console.error = err;
  }
}

test("parseFlags reads paths and options", () => {
  const f = parseFlags([
    "a.yml",
    "--json",
    "--fail-on",
    "medium",
    "--no-color",
  ]);
  assert.deepEqual(f.paths, ["a.yml"]);
  assert.equal(f.json, true);
  assert.equal(f.failOn, "medium");
  assert.equal(f.noColor, true);
});

test("parseFlags defaults fail-on to high", () => {
  assert.equal(parseFlags([]).failOn, "high");
});

test("main exits 1 on the insecure fixture and 0 on the clean one", () => {
  assert.equal(
    silent(() => main([fixture("insecure.yml"), "--json"])),
    1,
  );
  assert.equal(
    silent(() => main([fixture("clean.yml"), "--json"])),
    0,
  );
});

test("main respects --fail-on none (report only, never fails)", () => {
  assert.equal(
    silent(() =>
      main([fixture("insecure.yml"), "--fail-on", "none", "--json"]),
    ),
    0,
  );
});

test("main returns 2 when the file is missing", () => {
  assert.equal(
    silent(() => main(["definitely-not-here.yml"])),
    2,
  );
});

test("--ignore leaves out the rules you've accepted, repeatable or comma-separated", () => {
  assert.deepEqual(
    parseFlags(["--ignore", "hl009,HL008", "--ignore", " HL008 "]).ignore,
    ["HL008", "HL009"],
  );
  const lines: string[] = [];
  const log = console.log;
  console.log = (s: string) => lines.push(s);
  try {
    main([
      fixture("insecure.yml"),
      "--json",
      "--ignore",
      "HL001,HL002,HL003,HL004,HL005,HL006,HL007",
    ]);
  } finally {
    console.log = log;
  }
  const [report] = JSON.parse(lines.join("\n"));
  assert.ok(
    report.findings.every((f: { rule: string }) =>
      ["HL008", "HL009"].includes(f.rule),
    ),
  );
  assert.deepEqual(report.ignored.length, 7);
});

test("--ignore with a rule that doesn't exist is a usage error", () => {
  assert.equal(
    silent(() => main([fixture("insecure.yml"), "--ignore", "HL099"])),
    2,
  );
});

test("--strict turns on the opt-in rules", () => {
  assert.equal(parseFlags(["--strict"]).strict, true);
  assert.equal(parseFlags([]).strict, false);
});
