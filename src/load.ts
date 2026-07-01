import { readFileSync } from "node:fs";
import { parse } from "yaml";
import type { ComposeFile, EnvVar, Port, Service, Volume } from "./types.ts";

export function loadCompose(path: string): ComposeFile {
  return parseCompose(readFileSync(path, "utf8"), path);
}

export function parseCompose(text: string, path = "compose"): ComposeFile {
  const doc = parse(text) as unknown;
  const services: Service[] = [];
  const raw = isObject(doc) ? doc.services : undefined;
  if (isObject(raw)) {
    for (const [name, value] of Object.entries(raw)) {
      services.push(normalizeService(name, isObject(value) ? value : {}));
    }
  }
  return { path, services };
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
    privileged: s.privileged === true,
    networkMode:
      typeof s.network_mode === "string" ? s.network_mode : undefined,
    restart,
    hasRestartPolicy,
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
