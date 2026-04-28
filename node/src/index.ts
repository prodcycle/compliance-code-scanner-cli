import { ComplianceApiClient, ScanOptions, GateOptions, ScanResult } from './api-client';
import { collectFiles } from './utils/fs';

export * from './api-client';
export * from './formatters/table';
export * from './formatters/prompt';
export * from './formatters/sarif';

interface ScanReturn {
  scanId?: string;
  passed: boolean;
  exitCode: number;
  findings: unknown[];
  report: unknown;
  summary: unknown;
}

/**
 * Scan a repository by collecting files and sending them to the API.
 *
 * Modes (selectable via `options.config`):
 *   - default: synchronous validate; auto-falls-back to chunked sessions
 *     if the server returns 413 with `suggestedEndpoint=/v1/compliance/scans`
 *   - `mode: 'async'`: kicks off a 202 async-validate and polls until
 *     terminal (returns same shape as default)
 *   - `mode: 'chunked'`: explicit chunked-session flow regardless of size
 */
export async function scan(params: {
  repoPath: string;
  frameworks?: string[];
  options?: ScanOptions;
}): Promise<ScanReturn> {
  const { repoPath, frameworks = ['soc2'], options = {} } = params;

  const files = await collectFiles(repoPath, options.include, options.exclude);

  if (Object.keys(files).length === 0) {
    return {
      passed: true,
      exitCode: 0,
      findings: [],
      report: null,
      summary: undefined,
    };
  }

  const client = new ComplianceApiClient(options.apiUrl, options.apiKey);
  const mode = (options.config?.mode as 'sync' | 'async' | 'chunked' | undefined) ?? 'sync';

  let response: ScanResult;
  if (mode === 'async') {
    response = await client.validateAndPoll(files, frameworks, options);
  } else if (mode === 'chunked') {
    response = await client.validateChunked(files, frameworks, options);
  } else {
    response = await client.validate(files, frameworks, options);
  }

  return {
    scanId: response.scanId,
    passed: response.passed,
    exitCode: response.passed ? 0 : 1,
    findings: response.findings ?? [],
    report: (response as { report?: unknown }).report ?? null,
    summary: response.summary,
  };
}

/**
 * Gate code strings directly without writing to disk (low-latency hook
 * endpoint, used by coding-agent post-edit hooks).
 */
export async function gate(options: GateOptions) {
  const { files, frameworks = ['soc2'], ...scanOpts } = options;

  const client = new ComplianceApiClient(options.apiUrl, options.apiKey);
  const response = await client.hook(files, frameworks, scanOpts);

  return {
    passed: response.passed,
    exitCode: response.passed ? 0 : 1,
    findings: response.findings ?? [],
    prompt: response.prompt,
    summary: response.summary,
  };
}
