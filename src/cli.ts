#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { auditCompose, countBySeverity } from "./audit.ts";
import { parseCompose } from "./load.ts";
import { renderReport } from "./render.ts";
import { SEVERITY_ORDER } from "./types.ts";
import type { Finding, Severity } from "./types.ts";

const VERSION = "homelab-audit 0.1.0";

const USAGE = [
  "usage: homelab-audit [compose-file...] [--json] [--fail-on high|medium|low|none] [--no-color]",
  "",
  "Audits docker-compose files for common security and reliability foot-guns.",
  "Defaults to a compose file in the current directory when none is given.",
  "Exit: 0 clean/under threshold, 1 findings at/above --fail-on (default high), 2 usage/read error.",
].join("\n");

const DEFAULT_FILES = [
  "docker-compose.yml",
  "docker-compose.yaml",
  "compose.yml",
  "compose.yaml",
];

export interface Flags {
  paths: string[];
  json: boolean;
  failOn: Severity | "none";
  noColor: boolean;
  help: boolean;
  version: boolean;
}

export function parseFlags(args: string[]): Flags {
  const paths: string[] = [];
  let json = false;
  let failOn: Severity | "none" = "high";
  let noColor = false;
  let help = false;
  let version = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") json = true;
    else if (a === "--no-color") noColor = true;
    else if (a === "--help" || a === "-h") help = true;
    else if (a === "--version" || a === "-v") version = true;
    else if (a === "--fail-on") {
      const v = args[++i];
      if (v === "high" || v === "medium" || v === "low" || v === "none")
        failOn = v;
    } else paths.push(a);
  }
  return { paths, json, failOn, noColor, help, version };
}

function discoverDefault(): string[] {
  const found = DEFAULT_FILES.find((f) => existsSync(f));
  return found ? [found] : [];
}

export function main(argv: string[]): number {
  const flags = parseFlags(argv);
  if (flags.help) {
    console.log(USAGE);
    return 0;
  }
  if (flags.version) {
    console.log(VERSION);
    return 0;
  }

  const paths = flags.paths.length > 0 ? flags.paths : discoverDefault();
  if (paths.length === 0) {
    console.error(
      "no compose file given and none found in the current directory\n",
    );
    console.error(USAGE);
    return 2;
  }

  const reports: { path: string; findings: Finding[] }[] = [];
  for (const path of paths) {
    let text: string;
    try {
      text = readFileSync(path, "utf8");
    } catch {
      console.error(`cannot read ${path}`);
      return 2;
    }
    try {
      reports.push({ path, findings: auditCompose(parseCompose(text, path)) });
    } catch (err) {
      console.error(
        `cannot parse ${path}: ${err instanceof Error ? err.message : String(err)}`,
      );
      return 2;
    }
  }

  const color =
    !flags.noColor && process.stdout.isTTY === true && !process.env.NO_COLOR;
  if (flags.json) {
    const payload = reports.map((r) => ({
      path: r.path,
      summary: countBySeverity(r.findings),
      findings: r.findings,
    }));
    console.log(JSON.stringify(payload, null, 2));
  } else {
    console.log(
      reports.map((r) => renderReport(r.path, r.findings, color)).join("\n\n"),
    );
  }

  const threshold =
    flags.failOn === "none" ? Infinity : SEVERITY_ORDER[flags.failOn];
  const worst = reports
    .flatMap((r) => r.findings)
    .reduce((max, f) => Math.max(max, SEVERITY_ORDER[f.severity]), 0);
  return worst >= threshold ? 1 : 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
