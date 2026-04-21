# Agent Guidelines for prodcycle

## Project Overview

This repo publishes the `@prodcycle/prodcycle` (npm) and `prodcycle` (PyPI) packages — a multi-framework compliance scanner CLI that sends repository files to the ProdCycle REST API (`https://api.prodcycle.com/v1/compliance/validate` and `/v1/compliance/hook`) for SOC 2, HIPAA, and NIST CSF evaluation. Both packages are stdlib/minimal-dep wrappers around the hosted service — no policy evaluation happens client-side.

## Architecture

```
node/src/
  cli.ts           # Commander entry point — subcommands: scan, gate, hook, init
  index.ts         # Programmatic Node.js API (scan(), gate())
  api-client.ts    # POST /v1/compliance/validate and /v1/compliance/hook
  utils/fs.ts      # Tree-walk file collector with gitignore + size limits
  formatters/      # table.ts, sarif.ts, prompt.ts — render ScanReport
dist/              # Compiled TypeScript output (gitignored, built on publish)

python/src/prodcycle/
  cli.py           # argparse entry point — mirrors Node subcommands
  __init__.py      # Programmatic Python API (scan(), gate())
  api_client.py    # Same two endpoints, urllib-based
  utils/fs.py      # Mirrors Node fs.ts (stdlib-only glob-to-regex)
  formatters/      # table.py, sarif.py, prompt.py
```

The Node and Python implementations are intentionally kept symmetric — behavior (subcommand surface, file-collection rules, formatter output) must stay in lockstep.

## Subcommand surface

- `prodcycle scan [path]` — full repo scan (replaces the old top-level `prodcycle .`; the bare-path form still works via a back-compat shim that injects `scan`).
- `prodcycle gate` — evaluates a JSON payload of files from stdin (low-latency `/compliance/hook` endpoint).
- `prodcycle hook` — coding-agent post-edit hook. Reads stdin in multiple shapes (`{files}`, `{file_path, content}`, Claude Code PostToolUse `{tool_input: ...}`) or `--file <path>`.
- `prodcycle init` — writes compliance hook config for Claude Code / Cursor into the project (`.claude/settings.json`, `.cursor/hooks.json`). Auto-detects agents; supports `--agent`, `--force`, `--dir`.

## Key Commands

- `cd node && npm run build` — compile TypeScript into `node/dist/`
- Publish is automated — pushing a GitHub release triggers `.github/workflows/publish.yml`, which publishes both npm (with provenance) and PyPI (OIDC trusted publishing).

## Critical Rules

### Public package — no proprietary policies
These packages are published publicly; they must NOT contain OPA/Rego policy source, Cedar policies, or any evaluation logic. All evaluation runs server-side on the ProdCycle API.

### File collection constraints (`utils/fs.*`)

Both Node and Python collectors enforce identical limits:

- **256 KB per-file limit** — files larger than this are silently skipped to respect the API payload limit.
- **10,000 file cap** — remaining files beyond this are skipped with a warning on stderr.
- **Binary skipping** — basic heuristic (null-byte probe) to skip non-text files.
- **Gitignore parity** — the collector respects `.gitignore` at the repo root and prunes a hardcoded `SKIP_DIRS` set (node_modules, .git, dist, build, venv, __pycache__, etc.) on descent. This must match the server-side scanner's behavior (see `compliance-code-scanner` PR #1029 history).

### Error handling in the API client

- The client must throw an actionable error if `PC_API_KEY` is missing or the server returns 401/403.
- The ProdCycle API handles rate limiting and payload validation; the CLI should bubble those errors up without retry/backoff loops.

### Keeping Node and Python symmetric

When changing behavior in one language, update the other in the same PR. Drift between the two packages is a bug — users of both runtimes expect identical results for identical inputs.

### Testing

*(Tests to be implemented using Vitest (Node) and pytest (Python), mocking `fetch` / `urllib` at the boundary.)*
