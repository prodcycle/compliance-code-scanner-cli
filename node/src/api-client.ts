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
export class ApiError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly body: ApiErrorBody | null,
    public readonly retryAfterSeconds: number | null,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

const DEFAULT_API_URL = 'https://api.prodcycle.com';

/**
 * Read a positive integer from an env var or fall back to a default. Used
 * for the timeout / retry knobs below so operators can tune behavior in CI
 * without forking the CLI.
 */
function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

/**
 * Maximum retry attempts for 429/503 responses. After this many tries we
 * give up and surface the error to the caller.
 */
const MAX_RETRY_ATTEMPTS = envInt('PC_MAX_RETRY_ATTEMPTS', 4);

/**
 * Hard ceiling on Retry-After (seconds). Even if the server asks for more
 * than this we cap it so the CLI doesn't appear to hang indefinitely on a
 * misconfigured server.
 */
const MAX_RETRY_AFTER_SECONDS = envInt('PC_MAX_RETRY_AFTER_SECONDS', 300);

/**
 * Per-request fetch timeout. Without this a stalled connection would tie
 * up the CLI indefinitely, bypassing both the retry cap and the async-poll
 * deadline. Default is 2 minutes — long enough for the largest non-async
 * sync `/validate` call, short enough that a hung TCP socket gets aborted.
 */
const REQUEST_TIMEOUT_MS = envInt('PC_REQUEST_TIMEOUT_MS', 120_000);

/**
 * Conservative client-side chunk sizing for the chunked-session flow. The
 * /chunks endpoint accepts up to 50 MB / 2000 files per request, but most
 * customer payloads are well under this and smaller chunks shorten
 * tail-latency on a single saturated chunk. The server's per-content
 * findings cache means re-scans of unchanged files are O(1) regardless of
 * chunk size, so picking on the smaller side costs little.
 */
const DEFAULT_CHUNK_MAX_BYTES = envInt(
  'PC_DEFAULT_CHUNK_MAX_BYTES',
  5 * 1024 * 1024, // 5 MB
);
const DEFAULT_CHUNK_MAX_FILES = envInt('PC_DEFAULT_CHUNK_MAX_FILES', 200);

/**
 * Async-validate poll cadence. The server typically completes scans in
 * 10–60 s; polling every 2 s keeps the round-trip overhead bounded while
 * still feeling responsive in interactive use.
 */
const ASYNC_POLL_INTERVAL_MS = envInt('PC_ASYNC_POLL_INTERVAL_MS', 2000);
const ASYNC_POLL_TIMEOUT_MS = envInt(
  'PC_ASYNC_POLL_TIMEOUT_MS',
  10 * 60 * 1000, // 10 minutes
);

/**
 * Keys in `options.config` that route client-side behavior (sync /
 * async / chunked dispatch, chunk sizing) and MUST NOT be forwarded to
 * the server. Some endpoints validate `options` strictly and would 400
 * on unknown keys, so leaking these would silently break every call.
 */
const CLIENT_ONLY_CONFIG_KEYS = new Set([
  'mode',
  'chunkMaxBytes',
  'chunkMaxFiles',
]);

export class ComplianceApiClient {
  private apiUrl: string;
  private apiKey: string;

  constructor(apiUrl?: string, apiKey?: string) {
    this.apiUrl = apiUrl || process.env.PC_API_URL || DEFAULT_API_URL;
    this.apiKey = apiKey || process.env.PC_API_KEY || '';

    if (
      !this.apiKey &&
      process.env.NODE_ENV !== 'test' &&
      !process.env.PC_SUPPRESS_WARNINGS
    ) {
      process.stderr.write(
        'Warning: PC_API_KEY is not set. API calls will likely fail.\n',
      );
    }
  }

  /**
   * Synchronous validate. On a 413 with `details.suggestedEndpoint ===
   * '/v1/compliance/scans'`, silently falls back to the chunked-session
   * flow so large-repo CI jobs don't have to know the difference.
   */
  async validate(
    files: Record<string, string>,
    frameworks: string[],
    options: ScanOptions = {},
  ): Promise<ScanResult> {
    try {
      return await this.request('POST', '/v1/compliance/validate', {
        files,
        frameworks,
        options: this.buildOptions(options),
      });
    } catch (err) {
      if (
        err instanceof ApiError &&
        err.statusCode === 413 &&
        err.body?.error?.details?.suggestedEndpoint === '/v1/compliance/scans'
      ) {
        // Server says: this payload won't fit, use chunked sessions instead.
        // Fall back transparently — the caller asked for `validate`, the
        // semantics (single scanId with final findings) are preserved.
        return this.validateChunked(files, frameworks, options);
      }
      throw err;
    }
  }

  /**
   * Hook endpoint — small per-write call from coding agents. No
   * suggestedEndpoint fallback because /hook keeps the historical 50 MB
   * ceiling; if a single hook write exceeds that, the caller's batching
   * is the bug to fix.
   */
  async hook(
    files: Record<string, string>,
    frameworks: string[],
    options: ScanOptions = {},
  ): Promise<ScanResult> {
    return this.request('POST', '/v1/compliance/hook', {
      files,
      frameworks,
      options: this.buildOptions(options),
    });
  }

  // ─── Chunked sessions ───────────────────────────────────────────────────

  /**
   * Open a chunked scan session. Returns a `scanId` that subsequent
   * `appendChunk` / `completeSession` calls reference. Server-side TTL is
   * 30 minutes by default — abandoned sessions self-clean via the
   * stale-session reaper.
   */
  async openSession(
    frameworks: string[],
    options: ScanOptions = {},
  ): Promise<{ scanId: string; chunkSizeBytes: number; maxFilesPerChunk: number; expiresAt: string }> {
    return this.request('POST', '/v1/compliance/scans', {
      frameworks,
      options: this.buildOptions(options),
    });
  }

  /**
   * Append a chunk of files to an open session. Each call has its own
   * /hook-style cap (50 MB / 2000 files). The server caches per-content
   * findings, so re-scans of unchanged files are O(1).
   */
  async appendChunk(
    scanId: string,
    files: Record<string, string>,
  ): Promise<{ filesScanned: number; cachedFiles: number; findingsAdded: number }> {
    return this.request('POST', `/v1/compliance/scans/${encodeURIComponent(scanId)}/chunks`, {
      files,
    });
  }

  /**
   * Finalize a chunked session: flips status to COMPLETED, computes
   * summary + passed, returns final findings.
   */
  async completeSession(scanId: string): Promise<ScanResult> {
    return this.request(
      'POST',
      `/v1/compliance/scans/${encodeURIComponent(scanId)}/complete`,
      {},
    );
  }

  /**
   * High-level helper: open → append (in chunks) → complete. Returns the
   * same shape as `validate()` so callers that auto-fallback don't have
   * to special-case the result.
   *
   * Caller can pre-set `chunkMaxBytes` / `chunkMaxFiles` on `options.config`
   * to override the conservative defaults.
   */
  async validateChunked(
    files: Record<string, string>,
    frameworks: string[],
    options: ScanOptions = {},
  ): Promise<ScanResult> {
    const chunkMaxBytes =
      (options.config?.chunkMaxBytes as number | undefined) ?? DEFAULT_CHUNK_MAX_BYTES;
    const chunkMaxFiles =
      (options.config?.chunkMaxFiles as number | undefined) ?? DEFAULT_CHUNK_MAX_FILES;

    const session = await this.openSession(frameworks, options);

    const chunks = chunkFiles(files, chunkMaxBytes, chunkMaxFiles);
    for (const chunk of chunks) {
      await this.appendChunk(session.scanId, chunk);
    }

    const result = await this.completeSession(session.scanId);
    return { scanId: session.scanId, ...result };
  }

  // ─── Async validate ─────────────────────────────────────────────────────

  /**
   * Async-validate: returns a `scanId` immediately; caller polls
   * `getScan(scanId)` until status is COMPLETED or FAILED. Useful for CI
   * runners that don't want to hold a connection for a 60 s scan.
   */
  async validateAsync(
    files: Record<string, string>,
    frameworks: string[],
    options: ScanOptions = {},
  ): Promise<{ scanId: string }> {
    return this.request('POST', '/v1/compliance/validate?async=true', {
      files,
      frameworks,
      options: this.buildOptions(options),
    });
  }

  /**
   * Fetch the current state of any scan (sync, async, or chunked-session).
   */
  async getScan(scanId: string): Promise<ScanResult> {
    return this.request('GET', `/v1/compliance/scans/${encodeURIComponent(scanId)}`, null);
  }

  /**
   * High-level helper: kicks off an async-validate, polls until terminal,
   * returns the same shape as `validate()`.
   */
  async validateAndPoll(
    files: Record<string, string>,
    frameworks: string[],
    options: ScanOptions = {},
  ): Promise<ScanResult> {
    const { scanId } = await this.validateAsync(files, frameworks, options);
    const deadline = Date.now() + ASYNC_POLL_TIMEOUT_MS;

    // Always poll at least once, and always do one final poll *after*
    // the last sleep before declaring a timeout — otherwise a scan that
    // completes during the trailing sleep window would be reported as a
    // timeout even though the result is sitting on the server.
    while (true) {
      const scan = await this.getScan(scanId);
      if (scan.status === 'COMPLETED' || scan.status === 'FAILED') {
        return { scanId, ...scan };
      }
      if (Date.now() >= deadline) break;
      await sleep(ASYNC_POLL_INTERVAL_MS);
    }

    throw new Error(
      `Async validate scan ${scanId} did not complete within ${
        ASYNC_POLL_TIMEOUT_MS / 1000
      }s. Re-run with the same scanId to keep polling: prodcycle scans ${scanId}`,
    );
  }

  // ─── Internals ──────────────────────────────────────────────────────────

  private buildOptions(options: ScanOptions): Record<string, unknown> {
    const merged: Record<string, unknown> = {
      severity_threshold: options.severityThreshold,
      fail_on: options.failOn,
    };
    if (options.config && typeof options.config === 'object') {
      // Strip client-routing keys (mode / chunkMaxBytes / chunkMaxFiles)
      // before forwarding — they steer this SDK, not the server. The
      // server's `options` schema may reject unknown keys strictly, in
      // which case leaking these would cause 400s on every call.
      for (const [key, value] of Object.entries(options.config)) {
        if (CLIENT_ONLY_CONFIG_KEYS.has(key)) continue;
        merged[key] = value;
      }
    }
    return merged;
  }

  /**
   * Single HTTP request with:
   *   - auth header
   *   - 429/503 + Retry-After honoring (up to MAX_RETRY_ATTEMPTS)
   *   - structured error with parsed body so callers can introspect
   *     `details.suggestedEndpoint` etc.
   */
  private async request<T = ScanResult>(
    method: 'GET' | 'POST',
    endpoint: string,
    data: unknown,
  ): Promise<T> {
    const url = `${this.apiUrl.replace(/\/+$/, '')}${endpoint}`;

    let lastError: Error | null = null;
    for (let attempt = 0; attempt < MAX_RETRY_ATTEMPTS; attempt++) {
      let response: Response;
      try {
        response = await fetch(url, {
          method,
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
          },
          ...(data !== null ? { body: JSON.stringify(data) } : {}),
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        });
      } catch (networkErr: unknown) {
        // Connection-level failures (DNS, TCP, TLS). Treat as retryable up
        // to the same cap as 503 — the server may be momentarily down or
        // the network blip may resolve.
        lastError =
          networkErr instanceof Error ? networkErr : new Error(String(networkErr));
        if (attempt < MAX_RETRY_ATTEMPTS - 1) {
          await sleep(retryBackoffMs(attempt));
          continue;
        }
        throw new Error(`Failed to connect to ProdCycle API: ${lastError.message}`);
      }

      const responseText = await response.text();
      let parsed: unknown = null;
      try {
        parsed = responseText ? JSON.parse(responseText) : null;
      } catch {
        // Non-JSON body (e.g. ALB-level 502/504). Leave parsed as null;
        // the retry path below handles based on status code.
      }

      if (response.ok) {
        // Unwrap the API envelope only when the discriminant
        // {status: "success" | "error", statusCode, data} is present.
        // Bare key presence isn't enough: a `ScanResult` already has a
        // `status` field (PASSED/FAILED/IN_PROGRESS) and an open index
        // signature, so checking only for `'status' in parsed && 'data'
        // in parsed` would misidentify a scan result that happens to
        // include a `data` key as an envelope and silently drop the
        // top-level `passed`, `scanId`, `findings` fields.
        if (isApiEnvelope(parsed)) {
          return parsed.data as T;
        }
        return (parsed as T) ?? ({} as T);
      }

      // Non-2xx. Inspect the body + Retry-After to decide whether to retry.
      const retryAfterSeconds = parseRetryAfter(response.headers.get('retry-after'));
      const errorBody = (parsed as ApiErrorBody | null) ?? null;
      const errorMessage =
        errorBody?.error?.message ?? `API request failed with status ${response.status}`;

      const isRetryable = response.status === 429 || response.status === 503;
      if (isRetryable && attempt < MAX_RETRY_ATTEMPTS - 1) {
        const delayMs =
          retryAfterSeconds != null ? retryAfterSeconds * 1000 : retryBackoffMs(attempt);
        const cappedDelayMs = Math.min(delayMs, MAX_RETRY_AFTER_SECONDS * 1000);
        await sleep(cappedDelayMs);
        continue;
      }

      throw new ApiError(response.status, errorBody, retryAfterSeconds, errorMessage);
    }

    // Unreachable in practice: every iteration returns, throws, or
    // continues. Kept only to satisfy the type-checker that this method
    // always returns or throws.
    /* istanbul ignore next */
    throw lastError ?? new Error('Exhausted retries without a response');
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Exponential backoff with jitter for retryable errors that don't carry an
 * explicit Retry-After (network failures, malformed 503).
 */
function retryBackoffMs(attempt: number): number {
  const base = 1000 * 2 ** attempt; // 1s, 2s, 4s, 8s, ...
  const jitter = Math.random() * 500;
  return base + jitter;
}

/**
 * Parse Retry-After header. Spec allows either:
 *   - delta-seconds (an integer)
 *   - HTTP-date
 * We support both. Returns seconds as a non-negative integer, or null if
 * the header is missing/unparseable.
 */
/**
 * Detect the API's envelope shape strictly: a plain object whose
 * `status` is the discriminant string "success" or "error" and that
 * carries a `data` payload. Anything else (including a bare scan result
 * that happens to contain `status: "PASSED"` and a `data` key) is
 * passed through unchanged so we don't silently drop top-level fields.
 */
function isApiEnvelope(value: unknown): value is { status: 'success' | 'error'; data: unknown } {
  if (!value || typeof value !== 'object') return false;
  const v = value as Record<string, unknown>;
  return (v.status === 'success' || v.status === 'error') && 'data' in v;
}

function parseRetryAfter(value: string | null): number | null {
  if (!value) return null;
  const asInt = Number.parseInt(value, 10);
  if (!Number.isNaN(asInt)) return Math.max(0, asInt);
  const asDate = Date.parse(value);
  if (!Number.isNaN(asDate)) {
    return Math.max(0, Math.ceil((asDate - Date.now()) / 1000));
  }
  return null;
}

/**
 * Split a `{ path: content }` map into chunks that respect both a byte
 * cap and a file-count cap. UTF-8 byte-length is used since the server
 * counts the request body's bytes after JSON serialisation; this is a
 * conservative client-side approximation.
 */
// Per-file overhead in the JSON-serialized request body. Each entry is
// `"path":"content",` which adds two pairs of quotes (4 bytes), one
// colon, one comma, and a small margin for backslash-escapes inside the
// content. 16 bytes is a conservative upper bound; the goal is to avoid
// undersizing — the server enforces the real cap.
const PER_FILE_JSON_OVERHEAD = 16;

// One-time wrapper overhead for the chunk request body itself
// (`{"files":{...}}`).
const PER_CHUNK_JSON_OVERHEAD = 16;

export function chunkFiles(
  files: Record<string, string>,
  maxBytes: number,
  maxFiles: number,
): Record<string, string>[] {
  const chunks: Record<string, string>[] = [];
  let current: Record<string, string> = {};
  let currentBytes = PER_CHUNK_JSON_OVERHEAD;
  let currentCount = 0;

  for (const [filePath, content] of Object.entries(files)) {
    const fileBytes =
      Buffer.byteLength(content, 'utf8') +
      Buffer.byteLength(filePath, 'utf8') +
      PER_FILE_JSON_OVERHEAD;
    // If a single file exceeds the cap on its own we can't split it further
    // here — emit it as its own chunk and let the server's per-file cap (if
    // any) reject if needed. Common case: huge SQL dumps, generated bundles.
    if (fileBytes + PER_CHUNK_JSON_OVERHEAD > maxBytes) {
      if (currentCount > 0) {
        chunks.push(current);
        current = {};
        currentBytes = PER_CHUNK_JSON_OVERHEAD;
        currentCount = 0;
      }
      chunks.push({ [filePath]: content });
      continue;
    }
    if (currentBytes + fileBytes > maxBytes || currentCount + 1 > maxFiles) {
      chunks.push(current);
      current = {};
      currentBytes = PER_CHUNK_JSON_OVERHEAD;
      currentCount = 0;
    }
    current[filePath] = content;
    currentBytes += fileBytes;
    currentCount += 1;
  }

  if (currentCount > 0) {
    chunks.push(current);
  }

  return chunks;
}
