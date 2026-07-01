# CLAUDE.md — homelab-audit

Conventions for working on this repo. Follow these on every change.

## Scope discipline
- This is a fixed-scope v0.1: static analysis of docker-compose files against a
  built-in ruleset. Out of scope and binding: live Docker socket / container
  scanning, auto-fixing files, a web UI, non-compose formats. If something beyond
  scope seems warranted, add it to the README roadmap instead of building it.
- Stick to the stack: TypeScript on Node 24+, with `yaml` as the only runtime
  dependency; `typescript` + `@types/node` + `prettier` for dev. Do not add a new
  dependency without asking me first.

## Code style
- Write idiomatic, concise TypeScript. Prefer the simplest construct that reads
  clearly. Use `const` and narrow types.
- No redundant or explanatory comments. Comment only the non-obvious: a subtle
  decision, a workaround, or a "why". Prefer clear names over comments.
- Use `strict` TypeScript; no `any` unless genuinely unavoidable (justify it).
- Code must pass `tsc --noEmit` and `prettier --check` with no errors.
- No dead code, no commented-out code, no scattered TODOs.
- Keep modules small and single-purpose: types / load / rules / audit / render / cli.

## Project-specific rules
- This runs on Node's strip-only type-stripping (no build step). Avoid TS syntax
  it rejects at runtime even though `tsc` accepts it: parameter properties
  (`constructor(readonly x)`), `enum`, `namespace`, and decorators. Use plain
  fields + `const` objects. `node --test` catches these; `tsc` alone does not.
- Relative imports use the `.ts` extension (required by Node's resolver here).
- Every rule has a stable `HLNNN` id and returns `Finding[]`. A finding always
  carries a concrete `fix` line; never report a problem without saying what to do.
- Severity means something: `high` = real security hole, `medium` = risky default
  or likely mistake, `low` = reliability/hygiene. Don't inflate.
- Exit-code contract: 0 = clean or under `--fail-on` threshold, 1 = findings at or
  above the threshold (default `high`), 2 = usage/read/parse error.

## Tests
- Every logic module (load, rules, audit, cli) has tests. Tests run with
  `node --test`, make zero network calls, and use the `fixtures/` compose files.
- Tests must pass before a change is considered done. New rules ship with a
  fixture case that proves they fire and a case that proves they don't over-fire.

## Git
- Commit messages are concise and imperative ("add rule for exposed datastore
  ports"), with no filler.
- Do not commit, push, publish, or open a pull request without my explicit approval.
- Commit/PR attribution is disabled via ~/.claude/settings.json; do not reintroduce
  it in any other form.

## Working with me
- I am learning. When you write or change anything non-trivial, give me a short
  plain-English explanation in chat, NOT as code comments. The committed code stays
  clean; the teaching goes in the conversation.
- Build in small, focused steps. Be direct. Do not pad responses.
