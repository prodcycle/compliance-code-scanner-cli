# @prodcycle/prodcycle

Multi-framework policy-as-code compliance scanner for infrastructure and application code. Scans Terraform, Kubernetes, Docker, `.env`, and application source (TypeScript, Python, Go, Java, Ruby) against SOC 2, HIPAA, and NIST CSF policies.

This repository hosts both the npm (Node.js) package and the PyPI (Python) package wrappers around the ProdCycle compliance REST API (`https://api.prodcycle.com/v1/compliance/validate` & `https://api.prodcycle.com/v1/compliance/hook`).

## Features

- **3 compliance frameworks**: SOC 2, HIPAA, NIST CSF
- **Automated policy enforcement**: Server-side OPA/Rego and Cedar evaluation engines
- **Infrastructure scanning**: Terraform, Kubernetes manifests, Dockerfiles, `.env` files
- **Application code scanning**: TypeScript, Python, Go, Java, Ruby
- **CI/CD integration**: CLI with SARIF output for GitHub Code Scanning
- **Coding-agent hooks**: Real-time post-edit scanning for Claude Code, Cursor, and any stdin-capable agent
- **One-command agent setup**: `prodcycle init` writes compliance hook config for supported agents
- **Programmatic API**: Full TypeScript and Python API for custom integrations
- **Self-remediation**: `gate` returns actionable remediation prompts that coding agents can consume directly

## Installation

### Node.js (npm)
```bash
npm install -g @prodcycle/prodcycle
```

### GitHub Packages (npm alternative)
If you prefer to install from GitHub Packages, configure your npm to point to the ProdCycle scope:

```bash
echo "@prodcycle:registry=https://npm.pkg.github.com" > .npmrc
npm login --scope=@prodcycle --registry=https://npm.pkg.github.com
npm install @prodcycle/prodcycle
```

### Python (PyPI)
```bash
pip install prodcycle
```

## Quick Start

### CLI

The CLI is organised as subcommands: `scan`, `gate`, `hook`, and `init`.
(The bare `prodcycle <path>` form is kept as a back-compat shim for `prodcycle scan <path>`.)

```bash
# Scan current directory against SOC 2 and HIPAA
prodcycle scan . --framework soc2,hipaa

# Output as SARIF for GitHub Code Scanning
prodcycle scan . --framework soc2 --format sarif --output results.sarif

# Set severity threshold (only report HIGH and above)
prodcycle scan . --framework hipaa --severity-threshold high

# LLM-ready remediation prompt
prodcycle scan . --format prompt
```

### Agent hooks

Auto-configure compliance hooks for the coding agents it detects in your repo (Claude Code, Cursor):

```bash
prodcycle init
# or: prodcycle init --agent claude,cursor --force --dir .
```

Once configured, the agent will pipe each edit through `prodcycle hook`, which returns a remediation prompt when a finding is produced and exits non-zero to block the edit. You can also invoke the hook directly:

```bash
# From an agent — stdin is Claude Code PostToolUse payload or {file_path, content}
echo '{"file_path": "infra/main.tf", "content": "resource \"aws_s3_bucket\" ..."}' \
  | prodcycle hook

# Scan a file on disk instead of reading content from stdin
prodcycle hook --file infra/main.tf --framework soc2,hipaa
```

### `gate` (CI / pre-commit)

`gate` accepts a JSON payload of files on stdin and calls the low-latency hook endpoint:

```bash
echo '{"files": {"main.tf": "resource \"aws_s3_bucket\" ..."}}' \
  | prodcycle gate --framework soc2
```

### Programmatic API (TypeScript)

```typescript
import { scan, gate } from '@prodcycle/prodcycle';

// Full Repository Scan
const { findings, exitCode } = await scan({
  repoPath: '/path/to/repo',
  frameworks: ['soc2', 'hipaa'],
  options: {
    severityThreshold: 'high',
    failOn: ['critical', 'high'],
  },
});

console.log(`Found ${findings.length} findings`);
console.log(`Exit code: ${exitCode}`);

// Gate — evaluate in-memory file contents (for coding agents)
const result = await gate({
  files: {
    'src/config.ts': 'export const DB_PASSWORD = "hardcoded-secret";',
    'terraform/main.tf': 'resource "aws_s3_bucket" "data" { }',
  },
  frameworks: ['soc2', 'hipaa'],
});

if (!result.passed) {
  console.log('Compliance issues found:');
  console.log(result.prompt); // Pre-formatted remediation instructions
}
```

### Programmatic API (Python)

```python
from prodcycle import scan, gate

# Full Repository Scan
response = scan(
    repo_path='/path/to/repo',
    frameworks=['soc2', 'hipaa'],
    options={
        'severityThreshold': 'high',
        'failOn': ['critical', 'high'],
    }
)

print(f"Found {len(response['findings'])} findings")
print(f"Exit code: {response['exitCode']}")

# Gate — evaluate in-memory file contents (for coding agents)
result = gate(
    files={
        'src/config.ts': 'export const DB_PASSWORD = "hardcoded-secret";',
        'terraform/main.tf': 'resource "aws_s3_bucket" "data" { }',
    },
    frameworks=['soc2', 'hipaa'],
)

if not result['passed']:
    print('Compliance issues found:')
    print(result['prompt']) # Pre-formatted remediation instructions
```

## API Key

An API key is required for production use to authenticate with ProdCycle. Set it via environment variable:

```bash
export PC_API_KEY=pc_your_api_key_here
```

API keys are created through the ProdCycle dashboard.

## File collection

The scanner honours `.gitignore` at the repo root and prunes common dependency / build directories (`node_modules`, `.git`, `dist`, `build`, `venv`, `__pycache__`, …) during tree-walk. It also applies:

- **256 KB per-file limit** — larger files are skipped.
- **10,000 file cap** — files beyond the cap are skipped with a stderr warning.
- **Binary skipping** — non-text files are skipped via a null-byte probe.

Use `--include` / `--exclude` on `prodcycle scan` for custom glob patterns.

## Requirements

- Node.js >= 24.0.0
- Python >= 3.12

## License

MIT
