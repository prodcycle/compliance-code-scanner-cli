import { ScanOptions, GateOptions } from './api-client';
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
export declare function scan(params: {
    repoPath: string;
    frameworks?: string[];
    options?: ScanOptions;
}): Promise<ScanReturn>;
/**
 * Gate code strings directly without writing to disk (low-latency hook
 * endpoint, used by coding-agent post-edit hooks).
 */
export declare function gate(options: GateOptions): Promise<{
    passed: boolean;
    exitCode: number;
    findings: unknown[];
    prompt: string | undefined;
    summary: unknown;
}>;
