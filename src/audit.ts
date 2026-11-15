import { rules } from "./rules.ts";
import { SEVERITY_ORDER } from "./types.ts";
import type { ComposeFile, Finding, Severity } from "./types.ts";

export function auditCompose(
  file: ComposeFile,
  opts: { strict?: boolean } = {},
): Finding[] {
  const findings: Finding[] = [];
  for (const service of file.services) {
    const ignored = new Set(service.ignore ?? []);
    for (const rule of rules) {
      if (rule.optIn && !opts.strict) continue;
      if (!ignored.has(rule.id)) findings.push(...rule.check(service));
    }
  }
  return findings.sort(
    (a, b) =>
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
      a.service.localeCompare(b.service) ||
      a.rule.localeCompare(b.rule),
  );
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  return {
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
  };
}
