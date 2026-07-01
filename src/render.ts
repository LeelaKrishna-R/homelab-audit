import { countBySeverity } from "./audit.ts";
import type { Finding, Severity } from "./types.ts";

const COLOR: Record<Severity | "reset" | "bold" | "dim", string> = {
  high: "\x1b[31m",
  medium: "\x1b[33m",
  low: "\x1b[90m",
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
};

const TAG: Record<Severity, string> = {
  high: "HIGH",
  medium: "MED ",
  low: "LOW ",
};

export function renderReport(
  path: string,
  findings: Finding[],
  color: boolean,
): string {
  const paint = (code: string) => (color ? code : "");
  const lines: string[] = [
    `${paint(COLOR.bold)}homelab-audit${paint(COLOR.reset)}  ${path}`,
    "",
  ];

  if (findings.length === 0) {
    lines.push("  No issues found.");
    return lines.join("\n");
  }

  for (const f of findings) {
    lines.push(
      `  ${paint(COLOR[f.severity])}[${TAG[f.severity]}]${paint(COLOR.reset)} ` +
        `${paint(COLOR.bold)}${f.service}${paint(COLOR.reset)}  ${f.message}`,
    );
    lines.push(`         ${paint(COLOR.dim)}-> ${f.fix}${paint(COLOR.reset)}`);
  }

  const n = countBySeverity(findings);
  lines.push("", `  ${n.high} high, ${n.medium} medium, ${n.low} low`);
  return lines.join("\n");
}
