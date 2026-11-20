import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { auditCompose, countBySeverity } from "../src/audit.ts";
import { parseCompose } from "../src/load.ts";
import type { Finding } from "../src/types.ts";

const fixture = (name: string) =>
  readFileSync(
    fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url)),
    "utf8",
  );

const has = (findings: Finding[], rule: string, service: string) =>
  findings.some((f) => f.rule === rule && f.service === service);

test("the clean fixture produces zero findings", () => {
  assert.equal(auditCompose(parseCompose(fixture("clean.yml"))).length, 0);
});

test("the insecure fixture flags every expected issue", () => {
  const f = auditCompose(parseCompose(fixture("insecure.yml")));
  assert.ok(has(f, "HL001", "app"), "privileged");
  assert.ok(has(f, "HL002", "app"), "docker.sock mount");
  assert.ok(has(f, "HL003", "db"), "hardcoded password");
  assert.ok(has(f, "HL004", "app"), "SYS_ADMIN cap");
  assert.ok(has(f, "HL005", "db"), "exposed postgres");
  assert.ok(has(f, "HL006", "app"), "host network");
  assert.ok(has(f, "HL007", "app"), "writable /etc mount");
  assert.ok(has(f, "HL008", "db"), "no restart policy");
  assert.ok(has(f, "HL009", "cache"), "redis:latest");
  assert.ok(
    !f.some((x) => x.service === "proxy"),
    "loopback-bound, pinned, restarting proxy is clean",
  );
});

test("an exposed datastore port is high, a plain app port is medium", () => {
  const f = auditCompose(parseCompose(fixture("insecure.yml")));
  assert.equal(
    f.find((x) => x.rule === "HL005" && x.service === "db")?.severity,
    "high",
  );
  assert.equal(
    f.find((x) => x.rule === "HL005" && x.service === "app")?.severity,
    "medium",
  );
});

test("a loopback-bound port and a ${VAR} secret are not flagged", () => {
  const f = auditCompose(
    parseCompose(`
services:
  a:
    image: app:1.0
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:80"
    environment:
      API_TOKEN: \${MY_TOKEN}
`),
  );
  assert.equal(f.length, 0);
});

test("countBySeverity tallies every finding exactly once", () => {
  const f = auditCompose(parseCompose(fixture("insecure.yml")));
  const n = countBySeverity(f);
  assert.equal(n.high + n.medium + n.low, f.length);
  assert.ok(n.high >= 3);
});

test("HL010 (opt-in): a service with no healthcheck is flagged only with strict", () => {
  const yaml = `services:
  web:
    image: nginx:1.27
  db:
    image: postgres:16
    healthcheck:
      test: ["CMD", "pg_isready"]
  worker:
    image: busybox:1.36
    healthcheck:
      disable: true
  off:
    image: busybox:1.36
    healthcheck:
      test: ["NONE"]
`;
  const file = parseCompose(yaml);
  assert.ok(auditCompose(file).every((f) => f.rule !== "HL010"));
  const strict = auditCompose(file, { strict: true }).filter(
    (f) => f.rule === "HL010",
  );
  assert.deepEqual(strict.map((f) => f.service).sort(), [
    "off",
    "web",
    "worker",
  ]);
  assert.ok(strict.every((f) => f.severity === "low"));
});

test("HL011 (opt-in): a service with no memory limit is flagged only with strict", () => {
  const yaml = `services:
  web:
    image: nginx:1.27
  db:
    image: postgres:16
    mem_limit: 512m
  api:
    image: node:22
    deploy:
      resources:
        limits:
          memory: 256M
`;
  const file = parseCompose(yaml);
  assert.ok(auditCompose(file).every((f) => f.rule !== "HL011"));
  const strict = auditCompose(file, { strict: true }).filter(
    (f) => f.rule === "HL011",
  );
  assert.deepEqual(
    strict.map((f) => f.service),
    ["web"],
  );
});

test("HL012: security_opt that turns off seccomp, AppArmor or SELinux labels", () => {
  const yaml = `services:
  a:
    image: nginx:1.27
    security_opt:
      - seccomp:unconfined
      - no-new-privileges:true
  b:
    image: nginx:1.27
    security_opt: ["apparmor=unconfined", "label:disable"]
  c:
    image: nginx:1.27
    security_opt:
      - no-new-privileges:true
`;
  const found = auditCompose(parseCompose(yaml)).filter(
    (f) => f.rule === "HL012",
  );
  assert.deepEqual(
    found.map((f) => f.service),
    ["a", "b", "b"],
  );
  assert.ok(found.every((f) => f.severity === "medium"));
});

test("HL002: the Docker socket is caught under /run as well as /var/run", () => {
  const yaml = `services:
  a:
    image: portainer/portainer-ce:2.21.0
    volumes:
      - /run/docker.sock:/var/run/docker.sock
  b:
    image: traefik:3.1
    volumes:
      - type: bind
        source: /run/docker.sock
        target: /var/run/docker.sock
        read_only: true
  c:
    image: nginx:1.27
    volumes:
      - /run/app/app.sock:/run/app.sock
`;
  const found = auditCompose(parseCompose(yaml)).filter(
    (f) => f.rule === "HL002",
  );
  assert.deepEqual(
    found.map((f) => f.service),
    ["a", "b"],
  );
});

test("HL013 (opt-in): a service with no CPU limit is flagged only with strict", () => {
  const yaml = `services:
  web:
    image: nginx:1.27
  db:
    image: postgres:16
    cpus: 1.5
  api:
    image: node:22
    deploy:
      resources:
        limits:
          cpus: "0.50"
  worker:
    image: node:22
    cpu_quota: 50000
  unlimited:
    image: redis:7
    cpus: 0
  weighted:
    image: redis:7
    cpu_shares: 512
  templated:
    image: redis:7
    cpus: \${REDIS_CPUS}
`;
  const file = parseCompose(yaml);
  assert.ok(auditCompose(file).every((f) => f.rule !== "HL013"));
  const strict = auditCompose(file, { strict: true }).filter(
    (f) => f.rule === "HL013",
  );
  // zero means "no limit" to Docker, and cpu_shares is a weight, not a cap
  assert.deepEqual(strict.map((f) => f.service).sort(), [
    "unlimited",
    "web",
    "weighted",
  ]);
  assert.ok(strict.every((f) => f.severity === "low"));
});
