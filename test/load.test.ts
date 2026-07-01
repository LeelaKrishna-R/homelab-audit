import { test } from "node:test";
import assert from "node:assert/strict";
import { parseCompose } from "../src/load.ts";

test("normalizes the port short, long, and numeric forms", () => {
  const ports = parseCompose(`
services:
  a:
    ports:
      - "8080:80"
      - "127.0.0.1:9090:90"
      - "70"
      - 71
      - target: 100
        published: 8100
        host_ip: 0.0.0.0
`).services[0].ports;
  assert.equal(ports[0].hostIp, undefined);
  assert.equal(ports[0].containerPort, 80);
  assert.equal(ports[1].hostIp, "127.0.0.1");
  assert.equal(ports[1].containerPort, 90);
  assert.equal(ports[2].containerPort, 70);
  assert.equal(ports[3].containerPort, 71);
  assert.equal(ports[4].hostIp, "0.0.0.0");
  assert.equal(ports[4].containerPort, 100);
});

test("normalizes environment as both map and list", () => {
  const map = parseCompose(`
services:
  a:
    environment:
      FOO: bar
      NUM: 5
      EMPTY:
`).services[0].env;
  assert.deepEqual(
    map.find((e) => e.key === "FOO"),
    { key: "FOO", value: "bar" },
  );
  assert.equal(map.find((e) => e.key === "NUM")?.value, "5");
  assert.equal(map.find((e) => e.key === "EMPTY")?.value, undefined);

  const list = parseCompose(`
services:
  a:
    environment:
      - FOO=bar
      - BARE
`).services[0].env;
  assert.deepEqual(list[0], { key: "FOO", value: "bar" });
  assert.deepEqual(list[1], { key: "BARE" });
});

test("normalizes volumes and the read-only flag", () => {
  const volumes = parseCompose(`
services:
  a:
    volumes:
      - ./data:/data
      - /etc/localtime:/etc/localtime:ro
      - named:/var/lib
      - type: bind
        source: /srv
        target: /srv
        read_only: true
`).services[0].volumes;
  assert.deepEqual(volumes[0], {
    raw: "./data:/data",
    source: "./data",
    target: "/data",
    readOnly: false,
  });
  assert.equal(volumes[1].readOnly, true);
  assert.equal(volumes[2].source, "named");
  assert.equal(volumes[3].source, "/srv");
  assert.equal(volumes[3].readOnly, true);
});

test("detects a restart policy from the deploy block", () => {
  const service = parseCompose(`
services:
  a:
    deploy:
      restart_policy:
        condition: on-failure
`).services[0];
  assert.equal(service.hasRestartPolicy, true);
});

test("treats restart: no as having no policy", () => {
  const service = parseCompose(`
services:
  a:
    restart: "no"
`).services[0];
  assert.equal(service.hasRestartPolicy, false);
});
