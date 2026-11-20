import { readFileSync } from "node:fs";
import { isMap, isScalar, parseDocument } from "yaml";
import type { ComposeFile, EnvVar, Port, Service, Volume } from "./types.ts";

export function loadCompose(path: string): ComposeFile {
  return parseCompose(readFileSync(path, "utf8"), path);
}

export function parseCompose(text: string, path = "compose"): ComposeFile {
  const document = parseDocument(text);
  const doc = document.toJS() as unknown;
  const services: Service[] = [];
  const raw = isObject(doc) ? doc.services : undefined;
  const ignores = ignoreComments(text, document);
  if (isObject(raw)) {
    for (const [name, value] of Object.entries(raw)) {
      services.push({
        ...normalizeService(name, isObject(value) ? value : {}),
        ignore: ignores.get(name) ?? [],
      });
    }
  }
  return { path, services };
}

const IGNORE = /#\s*homelab-audit:\s*ignore\s+((?:HL\d{3}[\s,]*)+)/gi;

// Rules silenced per service by a `# homelab-audit: ignore HL001, HL005` comment in its block or on the lines
// directly above its name. Comments are gone once the YAML is parsed, so this reads the text by node position.
function ignoreComments(
  text: string,
  document: ReturnType<typeof parseDocument>,
): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const services = document.get("services", true);
  if (!isMap(services)) return out;
  for (const pair of services.items) {
    if (!isScalar(pair.key) || !pair.key.range) continue;
    let start = text.lastIndexOf("\n", pair.key.range[0] - 1) + 1;
    while (start > 0) {
      const prevStart = text.lastIndexOf("\n", start - 2) + 1;
      if (!text.slice(prevStart, start).trim().startsWith("#")) break;
      start = prevStart;
    }
    const valueRange = (
      pair.value as { range?: [number, number, number] } | null
    )?.range;
    const end = valueRange ? valueRange[2] : pair.key.range[2];
    const rules = new Set<string>();
    for (const m of text.slice(start, end).matchAll(IGNORE)) {
      for (const id of m[1].match(/HL\d{3}/gi) ?? [])
        rules.add(id.toUpperCase());
    }
    if (rules.size) out.set(String(pair.key.value), [...rules].sort());
  }
  return out;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function normalizeService(name: string, s: Record<string, unknown>): Service {
  const deploy = isObject(s.deploy) ? s.deploy : {};
  const restart = typeof s.restart === "string" ? s.restart : undefined;
  const hasRestartPolicy =
    (restart !== undefined && restart !== "no") ||
    deploy.restart_policy !== undefined;
  return {
    name,
    image: typeof s.image === "string" ? s.image : undefined,
    buildsLocally: s.build !== undefined,
    ports: normalizePorts(s.ports),
    env: normalizeEnv(s.environment),
    volumes: normalizeVolumes(s.volumes),
    capAdd: normalizeStringList(s.cap_add),
    securityOpt: normalizeStringList(s.security_opt),
    privileged: s.privileged === true,
    networkMode:
      typeof s.network_mode === "string" ? s.network_mode : undefined,
    restart,
    hasRestartPolicy,
    hasHealthcheck: runsHealthcheck(s.healthcheck),
    hasMemoryLimit: hasMemoryLimit(s, deploy),
    hasCpuLimit: hasCpuLimit(s, deploy),
  };
}

function normalizeStringList(v: unknown): string[] {
  if (Array.isArray(v))
    return v.filter((e): e is string => typeof e === "string");
  if (typeof v === "string") return [v];
  return [];
}

function toPort(v: unknown): number | undefined {
  const n = parseInt(String(v), 10);
  return Number.isNaN(n) ? undefined : n;
}

function normalizePorts(v: unknown): Port[] {
  if (!Array.isArray(v)) return [];
  return v.map((entry): Port => {
    if (typeof entry === "number")
      return { raw: String(entry), containerPort: entry };
    if (typeof entry === "string") return parsePortString(entry);
    if (isObject(entry)) {
      return {
        raw: JSON.stringify(entry),
        hostIp: typeof entry.host_ip === "string" ? entry.host_ip : undefined,
        containerPort: toPort(entry.target),
      };
    }
    return { raw: String(entry) };
  });
}

function parsePortString(s: string): Port {
  const addr = s.split("/")[0];
  // Compose wraps an IPv6 host_ip in brackets, e.g. [::1]:8080:80
  const bracket = addr.match(/^\[([^\]]+)\]:(.+)$/);
  if (bracket) {
    const tail = bracket[2].split(":");
    return {
      raw: s,
      hostIp: bracket[1],
      containerPort: toPort(tail[tail.length - 1]),
    };
  }
  const parts = addr.split(":");
  if (parts.length === 1) return { raw: s, containerPort: toPort(parts[0]) };
  if (parts.length === 2) return { raw: s, containerPort: toPort(parts[1]) };
  return { raw: s, hostIp: parts[0], containerPort: toPort(parts[2]) };
}

function normalizeEnv(v: unknown): EnvVar[] {
  if (Array.isArray(v)) {
    return v
      .filter((e): e is string => typeof e === "string")
      .map((e) => {
        const idx = e.indexOf("=");
        return idx === -1
          ? { key: e }
          : { key: e.slice(0, idx), value: e.slice(idx + 1) };
      });
  }
  if (isObject(v)) {
    return Object.entries(v).map(([key, value]) => ({
      key,
      value: value === null || value === undefined ? undefined : String(value),
    }));
  }
  return [];
}

function normalizeVolumes(v: unknown): Volume[] {
  if (!Array.isArray(v)) return [];
  return v.map((entry): Volume => {
    if (typeof entry === "string") return parseVolumeString(entry);
    if (isObject(entry)) {
      return {
        raw: JSON.stringify(entry),
        source: typeof entry.source === "string" ? entry.source : undefined,
        target: typeof entry.target === "string" ? entry.target : undefined,
        readOnly: entry.read_only === true,
      };
    }
    return { raw: String(entry), readOnly: false };
  });
}

function parseVolumeString(s: string): Volume {
  // Splitting on ":" assumes Linux paths; a Windows drive-letter source would mis-split.
  const parts = s.split(":");
  if (parts.length === 1) return { raw: s, target: parts[0], readOnly: false };
  const mode = parts.length >= 3 ? parts[2] : "";
  return {
    raw: s,
    source: parts[0],
    target: parts[1],
    readOnly: /(^|,)ro(,|$)/.test(mode),
  };
}

function runsHealthcheck(h: unknown): boolean {
  if (!isObject(h) || h.disable === true) return false;
  const test = h.test;
  if (Array.isArray(test))
    return !(test.length > 0 && String(test[0]).toUpperCase() === "NONE");
  return typeof test === "string" ? test.trim() !== "" : false;
}

/** A CPU cap Docker enforces. `cpu_shares` is only a weight under contention, so it is not one. */
function hasCpuLimit(
  s: Record<string, unknown>,
  deploy: Record<string, unknown>,
): boolean {
  const resources = isObject(deploy.resources) ? deploy.resources : {};
  const limits = isObject(resources.limits) ? resources.limits : {};
  return [s.cpus, s.cpu_quota, limits.cpus].some((v) => {
    if (typeof v !== "number" && typeof v !== "string") return false;
    const n = Number(v);
    // an unresolved ${VAR} is taken as set: its value is the user's to give
    return Number.isNaN(n) ? String(v).trim() !== "" : n > 0;
  });
}

function hasMemoryLimit(
  s: Record<string, unknown>,
  deploy: Record<string, unknown>,
): boolean {
  if (
    s.mem_limit !== undefined &&
    s.mem_limit !== null &&
    s.mem_limit !== 0 &&
    s.mem_limit !== "0"
  )
    return true;
  const resources = isObject(deploy.resources) ? deploy.resources : {};
  const limits = isObject(resources.limits) ? resources.limits : {};
  return limits.memory !== undefined && limits.memory !== null;
}
