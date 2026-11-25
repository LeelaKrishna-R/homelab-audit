export type Severity = "high" | "medium" | "low";

export const SEVERITY_ORDER: Record<Severity, number> = {
  high: 3,
  medium: 2,
  low: 1,
};

export interface Finding {
  rule: string;
  severity: Severity;
  service: string;
  message: string;
  fix: string;
}

export interface Port {
  raw: string;
  hostIp?: string;
  containerPort?: number;
}

export interface Volume {
  raw: string;
  source?: string;
  target?: string;
  readOnly: boolean;
}

export interface EnvVar {
  key: string;
  value?: string;
}

export interface Service {
  name: string;
  image?: string;
  buildsLocally: boolean;
  ports: Port[];
  env: EnvVar[];
  volumes: Volume[];
  capAdd: string[];
  /** `security_opt:` entries, as written. */
  securityOpt: string[];
  privileged: boolean;
  networkMode?: string;
  /** `pid:` and `ipc:` as written ("host", "service:db", …). */
  pidMode?: string;
  ipcMode?: string;
  /** Host paths of `devices:` entries (`/dev/sda:/dev/sda:r` → `/dev/sda`). */
  devices: string[];
  /** `userns_mode:` as written ("host" turns off the daemon's user-namespace remapping). */
  usernsMode?: string;
  /** `cgroup:` as written ("host" shares the host's cgroup namespace; "private" is the default on cgroup v2). */
  cgroupMode?: string;
  restart?: string;
  hasRestartPolicy: boolean;
  /** A `healthcheck:` that runs (not `disable: true`, not `test: ["NONE"]`). The image may still define one. */
  hasHealthcheck: boolean;
  /** `mem_limit:` or `deploy.resources.limits.memory`. */
  hasMemoryLimit: boolean;
  /** `cpus:`, `cpu_quota:` or `deploy.resources.limits.cpus`, above zero (zero means no limit). */
  hasCpuLimit: boolean;
  /** Rule ids silenced for this service by a `# homelab-audit: ignore …` comment. */
  ignore?: string[];
}

export interface ComposeFile {
  path: string;
  services: Service[];
}

export interface Rule {
  id: string;
  /** Fires on most services, so it runs only with --strict. */
  optIn?: boolean;
  check(service: Service): Finding[];
}
