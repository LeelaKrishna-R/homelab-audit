# homelab-audit

[![CI](https://github.com/LeelaKrishna-R/homelab-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/LeelaKrishna-R/homelab-audit/actions/workflows/ci.yml)

A small CLI that reads a `docker-compose.yml` and flags common security and
reliability foot-guns before they bite you. It is a linter for your self-hosted
stack: no Docker daemon, no network, no telemetry. It reads the file and prints
a prioritized list of problems with a concrete fix for each.

```
$ npx homelab-audit docker-compose.yml

homelab-audit  docker-compose.yml

  [HIGH] db     PostgreSQL port 5432 is published to all interfaces (0.0.0.0)
         -> Bind to a specific host, e.g. "127.0.0.1:5432:5432", or put it behind a reverse proxy
  [HIGH] db     Hardcoded secret in environment: POSTGRES_PASSWORD
         -> Move it to a git-ignored `.env` file, Docker secrets, or a `${VAR}` reference from the host env
  [HIGH] app    Runs in privileged mode (full access to host devices)
         -> Remove `privileged: true`; grant only the specific `cap_add` it needs
  [MED ] app    Uses host network mode (no network isolation from the host)
         -> Use a bridge network and publish only the ports you need
  [LOW ] cache  Image uses the :latest tag: redis:latest
         -> Pin a specific version tag so updates are intentional

  3 high, 1 medium, 1 low
```

## Why

Most homelab security problems are not exotic. They are the same handful of
defaults, copied from a random `docker-compose.yml` off the internet: a database
published to `0.0.0.0`, a password pasted straight into `environment:`, the
Docker socket mounted into a container that did not need it. `homelab-audit`
catches those in one command so you can fix them before something on your LAN
(or the internet) finds them first.

## Usage

No install needed:

```bash
npx homelab-audit                       # audits ./docker-compose.yml (or compose.yaml)
npx homelab-audit path/to/compose.yml   # audit a specific file
npx homelab-audit a.yml b.yml           # audit several files
npx homelab-audit --json                # machine-readable output
npx homelab-audit --fail-on medium      # exit non-zero on medium+ (for CI)
```

Requires Node 24+.

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Clean, or only findings below the `--fail-on` threshold |
| `1`  | Findings at or above `--fail-on` (default `high`) |
| `2`  | Usage error, or a file could not be read/parsed |

That makes it a drop-in CI gate. Add it to a workflow and a hardcoded password
or an exposed database fails the build:

```yaml
- run: npx homelab-audit docker-compose.yml --fail-on high
```

### Ignoring a finding you've accepted

Put a comment in the service's block, or on the line above its name:

```yaml
services:
  # homelab-audit: ignore HL006   # needs host networking for DHCP
  adguard:
    image: adguard/adguardhome
    network_mode: host
```

Only that service is affected, and only the rules you name.

## What it checks

| ID | Severity | Check |
|----|----------|-------|
| HL001 | high | Container runs `privileged: true` |
| HL002 | high | Mounts the Docker socket (`/var/run/docker.sock`) |
| HL003 | high | Hardcoded secret in `environment:` (password/token/key with a literal value) |
| HL004 | high / med | Dangerous `cap_add` (`SYS_ADMIN`, `ALL`, `SYS_MODULE` = high; others medium) |
| HL005 | high / med | Port published to all interfaces (`0.0.0.0`); a known datastore port = high |
| HL006 | medium | `network_mode: host` |
| HL007 | high / med | Mounts `/` (high) or a writable sensitive host path like `/etc`, `/root` (medium) |
| HL008 | low | No restart policy (won't survive a crash or reboot) |
| HL009 | low | Image uses `:latest` or is untagged |

Findings are advice, not gospel. A reverse proxy is supposed to publish 80/443
to the world; `homelab-audit` still lists it so you can confirm it is intentional.

## Roadmap

Kept deliberately small for v0.1. Likely next, roughly in order:

- **Live mode** (`--live`): read actually-running containers via the Docker
  socket and audit real state, not just the declared file.
- **Ignore file**: a `.homelab-audit.yml` to silence rules without touching the
  compose file (inline `# homelab-audit: ignore` comments already work).
- **More rules, opt-in**: missing healthcheck, no memory/CPU limits, `:latest` on
  `build` images. These fire on almost every service, so they will be opt-in to
  keep the default output sharp.
- **Container image**: `docker run ghcr.io/…/homelab-audit` so people can run it
  with Docker alone, no Node required.

Have a check you keep wishing existed? Open an issue.

## Development

```bash
npm install
npm test           # node --test, no network
npm run typecheck  # tsc --noEmit
npm run audit fixtures/insecure.yml
```

Runs directly on Node 24's native TypeScript type-stripping, so there is no build
step. See [CLAUDE.md](CLAUDE.md) for conventions.

## License

MIT
