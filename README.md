# @prodcycle/compliance-code-scanner

Multi-framework policy-as-code compliance scanner for infrastructure and application code. Scans Terraform, Kubernetes, Docker, `.env`, and application source (TypeScript, Python, Go, Java, Ruby) against SOC 2, HIPAA, and NIST CSF policies.

This package acts as a lightweight Node.js wrapper around the ProdCycle compliance REST API (`https://api.prodcycle.com/v1/compliance/validate` & `https://api.prodcycle.com/v1/compliance/hook`).

## Features

- **3 compliance frameworks**: SOC 2, HIPAA, NIST CSF
- **Automated policy enforcement**: Server-side OPA/Rego and Cedar evaluation engines
- **Infrastructure scanning**: Terraform, Kubernetes manifests, Dockerfiles, `.env` files
- **Application code scanning**: TypeScript, Python, Go, Java, Ruby
- **CI/CD integration**: CLI with SARIF output for GitHub Code Scanning
- **Programmatic API**: Full TypeScript API for custom integrations
- **Self-remediation**: `gate()` function returns actionable remediation prompts

## Installation

```bash
npm install -g @prodcycle/compliance-code-scanner
```

## Quick Start

### CLI

```bash
# Scan current directory against SOC 2 and HIPAA
npx compliance-code-scanner . --framework soc2,hipaa

# Output as SARIF for GitHub Code Scanning
npx compliance-code-scanner . --framework soc2 --format sarif --output results.sarif

# Set severity threshold (only report HIGH and above)
npx compliance-code-scanner . --framework hipaa --severity-threshold high
```

### Programmatic API

```typescript
import { scan, gate } from '@prodcycle/compliance-code-scanner';

// Full Repository Scan
const { report, findings, exitCode } = await scan({
  repoPath: '/path/to/repo',
  frameworks: ['soc2', 'hipaa'],
  options: {
    severityThreshold: 'high',
    failOn: ['critical', 'high'],
  },
});

console.log(`Found ${findings.length} findings`);
console.log(`Exit code: ${exitCode}`);

// Gate function (for coding agents)
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

## API Key

An API key is required for production use to authenticate with ProdCycle. Set it via environment variable:

```bash
export PC_API_KEY=pc_your_api_key_here
```

Or pass it programmatically:

```typescript
const result = await scan({
  repoPath: '.',
  frameworks: ['soc2'],
  options: { apiKey: 'pc_your_api_key_here' },
});
```

API keys are created through the ProdCycle dashboard.

## Requirements

- Node.js >= 24.0.0

## License

MIT
