import type { Finding, Rule } from "./types.ts";

const SENSITIVE_PORTS = new Map<number, string>([
  [1433, "SQL Server"],
  [2375, "Docker API"],
  [2376, "Docker API"],
  [3306, "MySQL"],
  [5432, "PostgreSQL"],
  [5672, "RabbitMQ"],
  [5984, "CouchDB"],
  [6379, "Redis"],
  [9200, "Elasticsearch"],
  [11211, "Memcached"],
  [15672, "RabbitMQ management"],
  [27017, "MongoDB"],
]);

const WILDCARD_IPS = new Set(["", "0.0.0.0", "::", "::0", "0.0.0.0/0"]);

const SECRET_KEY =
  /(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|_key)$/i;

const DANGEROUS_CAPS = /^(SYS_ADMIN|NET_ADMIN|ALL|SYS_PTRACE|SYS_MODULE)$/i;
const HIGH_CAPS = /^(SYS_ADMIN|ALL|SYS_MODULE)$/i;

const SENSITIVE_ROOTS = ["/etc", "/root", "/var/run", "/proc", "/sys", "/boot"];
const BENIGN_MOUNTS = new Set(["/etc/localtime", "/etc/timezone"]);

// /var/run is a symlink to /run on current distros, so both paths are the same socket.
const DOCKER_SOCKETS = new Set(["/var/run/docker.sock", "/run/docker.sock"]);

const isWildcard = (hostIp: string | undefined): boolean =>
  hostIp === undefined || WILDCARD_IPS.has(hostIp);

const isLiteralSecret = (value: string | undefined): boolean =>
  value !== undefined &&
  value.trim() !== "" &&
  !value.includes("${") &&
  !/^\$[A-Za-z]/.test(value);

function imageTag(image: string): string | undefined {
  if (image.includes("@")) return "digest";
  const lastSlash = image.lastIndexOf("/");
  const lastColon = image.lastIndexOf(":");
  return lastColon > lastSlash ? image.slice(lastColon + 1) : undefined;
}

export const rules: Rule[] = [
  {
    id: "HL001",
    check: (s): Finding[] =>
      s.privileged
        ? [
            {
              rule: "HL001",
              severity: "high",
              service: s.name,
              message: "Runs in privileged mode (full access to host devices)",
              fix: "Remove `privileged: true`; grant only the specific `cap_add` it needs",
            },
          ]
        : [],
  },
  {
    id: "HL002",
    check: (s): Finding[] =>
      s.volumes
        .filter((v) => v.source !== undefined && DOCKER_SOCKETS.has(v.source))
        .map((): Finding => ({
          rule: "HL002",
          severity: "high",
          service: s.name,
          message: "Mounts the Docker socket (equivalent to root on the host)",
          fix: "Avoid mounting docker.sock; if a tool truly needs it, front it with a least-privilege socket proxy",
        })),
  },
  {
    id: "HL003",
    check: (s): Finding[] =>
      s.env
        .filter(
          (e) =>
            SECRET_KEY.test(e.key) &&
            !/public/i.test(e.key) &&
            isLiteralSecret(e.value),
        )
        .map((e): Finding => ({
          rule: "HL003",
          severity: "high",
          service: s.name,
          message: `Hardcoded secret in environment: ${e.key}`,
          fix: "Move it to a git-ignored `.env` file, Docker secrets, or a `${VAR}` reference from the host env",
        })),
  },
  {
    id: "HL004",
    check: (s): Finding[] =>
      s.capAdd
        .filter((c) => DANGEROUS_CAPS.test(c))
        .map((c): Finding => ({
          rule: "HL004",
          severity: HIGH_CAPS.test(c) ? "high" : "medium",
          service: s.name,
          message: `Adds dangerous capability: ${c}`,
          fix: "Drop it unless required; prefer the narrowest capability that works",
        })),
  },
  {
    id: "HL005",
    check: (s): Finding[] =>
      s.ports
        .filter((p) => isWildcard(p.hostIp))
        .map((p): Finding => {
          const datastore =
            p.containerPort !== undefined
              ? SENSITIVE_PORTS.get(p.containerPort)
              : undefined;
          const label =
            p.containerPort !== undefined
              ? `port ${p.containerPort}`
              : `port ${p.raw}`;
          const bind = p.containerPort ?? "PORT";
          return {
            rule: "HL005",
            severity: datastore ? "high" : "medium",
            service: s.name,
            message: datastore
              ? `${datastore} ${label} is published to all interfaces (0.0.0.0)`
              : `Published ${label} is bound to all interfaces (0.0.0.0)`,
            fix: `Bind to a specific host, e.g. "127.0.0.1:${bind}:${bind}", or put it behind a reverse proxy`,
          };
        }),
  },
  {
    id: "HL006",
    check: (s): Finding[] =>
      s.networkMode === "host"
        ? [
            {
              rule: "HL006",
              severity: "medium",
              service: s.name,
              message:
                "Uses host network mode (no network isolation from the host)",
              fix: "Use a bridge network and publish only the ports you need",
            },
          ]
        : [],
  },
  {
    // pid: host lets the container see every process on the host and, as root, signal or ptrace them;
    // ipc: host shares the host's shared memory and semaphores. "service:x" / "container:x" share with one container.
    id: "HL015",
    check: (s): Finding[] => [
      ...(s.pidMode === "host"
        ? [
            {
              rule: "HL015",
              severity: "high" as const,
              service: s.name,
              message:
                "Shares the host's process namespace (`pid: host`): it can see and signal every process on the host",
              fix: 'Remove `pid: host`; to watch another container, use `pid: "service:<name>"` instead',
            },
          ]
        : []),
      ...(s.ipcMode === "host"
        ? [
            {
              rule: "HL015",
              severity: "medium" as const,
              service: s.name,
              message:
                "Shares the host's IPC namespace (`ipc: host`): host shared memory and semaphores are readable",
              fix: 'Remove `ipc: host`, or share with one container (`ipc: "service:<name>"`)',
            },
          ]
        : []),
    ],
  },
  {
    // /dev/mem, /dev/kmem and /dev/port are raw host memory and I/O ports; a whole disk or partition lets the
    // container read every file on it regardless of permissions. GPU and USB nodes (/dev/dri, /dev/ttyUSB0) are fine.
    id: "HL016",
    check: (s): Finding[] =>
      s.devices.flatMap((d): Finding[] => {
        if (/^\/dev\/(?:mem|kmem|port)$/.test(d))
          return [
            {
              rule: "HL016",
              severity: "high",
              service: s.name,
              message: `Passes the host's raw memory device into the container: ${d}`,
              fix: `Remove ${d} from devices:; nothing in a container should need it`,
            },
          ];
        if (
          /^\/dev\/(?:sd[a-z]+\d*|hd[a-z]+\d*|vd[a-z]+\d*|xvd[a-z]+\d*|nvme\d+n\d+(?:p\d+)?|mmcblk\d+(?:p\d+)?|disk\/.+)$/.test(
            d,
          )
        )
          return [
            {
              rule: "HL016",
              severity: "medium",
              service: s.name,
              message: `Passes a raw host disk into the container: ${d} (every file on it is readable)`,
              fix: "Mount the directory it needs as a volume instead of the whole device",
            },
          ];
        return [];
      }),
  },
  {
    id: "HL007",
    check: (s): Finding[] =>
      s.volumes.flatMap((v): Finding[] => {
        const source = v.source;
        if (!source || !source.startsWith("/")) return [];
        if (DOCKER_SOCKETS.has(source)) return [];
        if (source === "/")
          return [
            {
              rule: "HL007",
              severity: "high",
              service: s.name,
              message: `Mounts the entire host filesystem at ${v.target ?? "/"}`,
              fix: "Mount only the specific directory the service needs",
            },
          ];
        if (BENIGN_MOUNTS.has(source)) return [];
        const hit = SENSITIVE_ROOTS.find(
          (r) => source === r || source.startsWith(`${r}/`),
        );
        if (hit && !v.readOnly)
          return [
            {
              rule: "HL007",
              severity: "medium",
              service: s.name,
              message: `Writable mount of sensitive host path: ${source}`,
              fix: "Mount it read-only (`:ro`) or scope it to a subdirectory the service owns",
            },
          ];
        return [];
      }),
  },
  {
    id: "HL008",
    check: (s): Finding[] =>
      s.hasRestartPolicy
        ? []
        : [
            {
              rule: "HL008",
              severity: "low",
              service: s.name,
              message:
                "No restart policy (won't come back after a crash or host reboot)",
              fix: "Add `restart: unless-stopped`",
            },
          ],
  },
  {
    id: "HL009",
    check: (s): Finding[] => {
      if (s.buildsLocally || !s.image) return [];
      const tag = imageTag(s.image);
      if (tag === undefined)
        return [
          {
            rule: "HL009",
            severity: "low",
            service: s.name,
            message: `Image is untagged (implicitly :latest): ${s.image}`,
            fix: "Pin a specific version tag for reproducible deploys",
          },
        ];
      if (tag === "latest")
        return [
          {
            rule: "HL009",
            severity: "low",
            service: s.name,
            message: `Image uses the :latest tag: ${s.image}`,
            fix: "Pin a specific version tag so updates are intentional",
          },
        ];
      return [];
    },
  },
  {
    id: "HL010",
    optIn: true,
    check: (s): Finding[] =>
      s.hasHealthcheck
        ? []
        : [
            {
              rule: "HL010",
              severity: "low",
              service: s.name,
              message:
                "No healthcheck in the compose file (the image may define one)",
              fix: "Add a `healthcheck:` so Docker knows when it is actually ready, not just running",
            },
          ],
  },
  {
    id: "HL011",
    optIn: true,
    check: (s): Finding[] =>
      s.hasMemoryLimit
        ? []
        : [
            {
              rule: "HL011",
              severity: "low",
              service: s.name,
              message:
                "No memory limit (a leak can take the whole host's memory)",
              fix: "Set `mem_limit:` (or `deploy.resources.limits.memory`) to what it needs plus headroom",
            },
          ],
  },
  {
    id: "HL012",
    check: (s): Finding[] =>
      s.securityOpt
        .filter((o) =>
          /^(seccomp|apparmor)\s*[:=]\s*unconfined$|^label\s*[:=]\s*disable$/i.test(
            o.trim(),
          ),
        )
        .map((o) => ({
          rule: "HL012",
          severity: "medium",
          service: s.name,
          message: `\`security_opt: ${o.trim()}\` turns off a kernel guard the container runtime applies by default`,
          fix: "Remove it; if one syscall or path is the problem, allow just that with a custom profile",
        })),
  },
  {
    id: "HL013",
    optIn: true,
    check: (s): Finding[] =>
      s.hasCpuLimit
        ? []
        : [
            {
              rule: "HL013",
              severity: "low",
              service: s.name,
              message:
                "No CPU limit (a runaway loop can starve everything else on the host)",
              fix: "Set `cpus:` (or `deploy.resources.limits.cpus`), e.g. `cpus: 1.5`",
            },
          ],
  },
  {
    id: "HL014",
    optIn: true,
    check: (s): Finding[] => {
      if (!s.buildsLocally || !s.image) return [];
      const tag = imageTag(s.image);
      if (tag !== undefined && tag !== "latest") return [];
      return [
        {
          rule: "HL014",
          severity: "low",
          service: s.name,
          message: `Built locally and tagged ${tag === undefined ? "with no tag (implicitly :latest)" : ":latest"}: ${s.image}`,
          fix: "Tag each build with a version (`image: myapp:1.4.2`) so you can roll back to the last good one",
        },
      ];
    },
  },
];
