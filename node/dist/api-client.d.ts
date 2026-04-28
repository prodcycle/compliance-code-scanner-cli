export interface ScanOptions {
    severityThreshold?: 'low' | 'medium' | 'high' | 'critical';
    failOn?: ('low' | 'medium' | 'high' | 'critical')[];
    include?: string[];
    exclude?: string[];
    apiKey?: string;
    apiUrl?: string;
    config?: Record<string, unknown>;
}
export interface GateOptions {
    files: Record<string, string>;
    frameworks?: string[];
    severityThreshold?: 'low' | 'medium' | 'high' | 'critical';
    failOn?: ('low' | 'medium' | 'high' | 'critical')[];
    apiKey?: string;
    apiUrl?: string;
    config?: Record<string, unknown>;
}
export interface ScanResult {
    scanId?: string;
    passed: boolean;
    findingsCount?: number;
    findings?: unknown[];
    summary?: unknown;
    prompt?: string;
    status?: 'IN_PROGRESS' | 'COMPLETED' | 'FAILED';
    [key: string]: unknown;
}
interface ApiErrorBody {
    status: 'error';
    statusCode: number;
    error?: {
        type?: string;
        message?: string;
        suggestion?: string;
        details?: {
            maxBytes?: number;
            maxFiles?: number;
            chunkSizeBytes?: number;
            receivedBytes?: number;
            suggestedEndpoint?: string;
            [key: string]: unknown;
        };
    };
}
/**
 * Error thrown for any non-2xx response. Carries the parsed body + status so
 * callers can branch on `details.suggestedEndpoint` (413 → chunked-session
 * fallback) or `Retry-After` (429 / 503 → backoff + retry).
 */
export declare class ApiError extends Error {
    readonly statusCode: number;
    readonly body: ApiErrorBody | null;
    readonly retryAfterSeconds: number | null;
    constructor(statusCode: number, body: ApiErrorBody | null, retryAfterSeconds: number | null, message: string);
}
export declare class ComplianceApiClient {
    private apiUrl;
    private apiKey;
    constructor(apiUrl?: string, apiKey?: string);
    /**
     * Synchronous validate. On a 413 with `details.suggestedEndpoint ===
     * '/v1/compliance/scans'`, silently falls back to the chunked-session
     * flow so large-repo CI jobs don't have to know the difference.
     */
    validate(files: Record<string, string>, frameworks: string[], options?: ScanOptions): Promise<ScanResult>;
    /**
     * Hook endpoint — small per-write call from coding agents. No
     * suggestedEndpoint fallback because /hook keeps the historical 50 MB
     * ceiling; if a single hook write exceeds that, the caller's batching
     * is the bug to fix.
     */
    hook(files: Record<string, string>, frameworks: string[], options?: ScanOptions): Promise<ScanResult>;
    /**
     * Open a chunked scan session. Returns a `scanId` that subsequent
     * `appendChunk` / `completeSession` calls reference. Server-side TTL is
     * 30 minutes by default — abandoned sessions self-clean via the
     * stale-session reaper.
     */
    openSession(frameworks: string[], options?: ScanOptions): Promise<{
        scanId: string;
        chunkSizeBytes: number;
        maxFilesPerChunk: number;
        expiresAt: string;
    }>;
    /**
     * Append a chunk of files to an open session. Each call has its own
     * /hook-style cap (50 MB / 2000 files). The server caches per-content
     * findings, so re-scans of unchanged files are O(1).
     */
    appendChunk(scanId: string, files: Record<string, string>): Promise<{
        filesScanned: number;
        cachedFiles: number;
        findingsAdded: number;
    }>;
    /**
     * Finalize a chunked session: flips status to COMPLETED, computes
     * summary + passed, returns final findings.
     */
    completeSession(scanId: string): Promise<ScanResult>;
    /**
     * High-level helper: open → append (in chunks) → complete. Returns the
     * same shape as `validate()` so callers that auto-fallback don't have
     * to special-case the result.
     *
     * Caller can pre-set `chunkMaxBytes` / `chunkMaxFiles` on `options.config`
     * to override the conservative defaults.
     */
    validateChunked(files: Record<string, string>, frameworks: string[], options?: ScanOptions): Promise<ScanResult>;
    /**
     * Async-validate: returns a `scanId` immediately; caller polls
     * `getScan(scanId)` until status is COMPLETED or FAILED. Useful for CI
     * runners that don't want to hold a connection for a 60 s scan.
     */
    validateAsync(files: Record<string, string>, frameworks: string[], options?: ScanOptions): Promise<{
        scanId: string;
    }>;
    /**
     * Fetch the current state of any scan (sync, async, or chunked-session).
     */
    getScan(scanId: string): Promise<ScanResult>;
    /**
     * High-level helper: kicks off an async-validate, polls until terminal,
     * returns the same shape as `validate()`.
     */
    validateAndPoll(files: Record<string, string>, frameworks: string[], options?: ScanOptions): Promise<ScanResult>;
    private buildOptions;
    /**
     * Single HTTP request with:
     *   - auth header
     *   - 429/503 + Retry-After honoring (up to MAX_RETRY_ATTEMPTS)
     *   - structured error with parsed body so callers can introspect
     *     `details.suggestedEndpoint` etc.
     */
    private request;
}
export declare function chunkFiles(files: Record<string, string>, maxBytes: number, maxFiles: number): Record<string, string>[];
export {};
