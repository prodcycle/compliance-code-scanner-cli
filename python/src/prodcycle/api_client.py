"""ProdCycle Compliance API client.

Thin HTTP client for https://api.prodcycle.com/v1/compliance/* — no
proprietary policies or scanner code is bundled in the SDK; everything
runs server-side.

Mirrors node/src/api-client.ts so the two SDKs stay feature-equivalent.
"""

import json
import math
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_API_URL = "https://api.prodcycle.com"


def _env_int(name, fallback):
    """Read a positive integer from an env var or fall back to a default.

    Used for the timeout / retry knobs below so operators can tune the
    client in CI without forking the SDK.
    """
    raw = os.environ.get(name)
    if not raw:
        return fallback
    try:
        parsed = int(raw)
    except ValueError:
        return fallback
    return parsed if parsed > 0 else fallback


# Maximum retry attempts for 429/503 responses. After this many tries we
# give up and surface the error to the caller.
MAX_RETRY_ATTEMPTS = _env_int("PC_MAX_RETRY_ATTEMPTS", 4)

# Hard ceiling on Retry-After (seconds). Even if the server asks for more
# than this we cap it so the CLI doesn't appear to hang indefinitely on a
# misconfigured server.
MAX_RETRY_AFTER_SECONDS = _env_int("PC_MAX_RETRY_AFTER_SECONDS", 300)

# Per-request socket timeout. Without this `urllib.request.urlopen` would
# block indefinitely on a stalled server, bypassing the retry cap and the
# async-poll deadline. Default is 2 minutes — long enough for the largest
# non-async sync `/validate` call.
REQUEST_TIMEOUT_S = _env_int("PC_REQUEST_TIMEOUT_S", 120)

# Conservative client-side chunk sizing for the chunked-session flow.
# /chunks accepts up to 50 MB / 2000 files per request, but smaller chunks
# shorten tail-latency on a single saturated chunk; the server's per-content
# findings cache keeps re-scans of unchanged files O(1) regardless of chunk
# size, so picking on the smaller side costs little.
DEFAULT_CHUNK_MAX_BYTES = _env_int("PC_DEFAULT_CHUNK_MAX_BYTES", 5 * 1024 * 1024)
DEFAULT_CHUNK_MAX_FILES = _env_int("PC_DEFAULT_CHUNK_MAX_FILES", 200)

# Async-validate poll cadence.
ASYNC_POLL_INTERVAL_S = _env_int("PC_ASYNC_POLL_INTERVAL_S", 2)
ASYNC_POLL_TIMEOUT_S = _env_int("PC_ASYNC_POLL_TIMEOUT_S", 10 * 60)

# Keys in `options['config']` that route client-side behavior (sync / async
# / chunked, chunk sizing) and MUST NOT be forwarded to the server. The
# server's `options` schema rejects unknown keys strictly on some endpoints,
# so leaking these would cause 400s rather than just being inert.
_CLIENT_ONLY_CONFIG_KEYS = frozenset({"mode", "chunkMaxBytes", "chunkMaxFiles"})


class ApiError(Exception):
    """Raised for any non-2xx API response.

    Carries the parsed error body + status so callers can branch on
    ``body['error']['details']['suggestedEndpoint']`` (413 → chunked-session
    fallback) or ``retry_after_seconds`` (429 / 503 → backoff + retry).
    """

    def __init__(self, status_code, body, retry_after_seconds, message):
        super().__init__(message)
        self.status_code = status_code
        self.body = body
        self.retry_after_seconds = retry_after_seconds


class ComplianceApiClient:
    def __init__(self, api_url=None, api_key=None):
        self.api_url = (
            (api_url or os.environ.get("PC_API_URL") or DEFAULT_API_URL).rstrip("/")
        )
        self.api_key = api_key or os.environ.get("PC_API_KEY", "")

        if (
            not self.api_key
            and os.environ.get("PYTEST_CURRENT_TEST") is None
            and not os.environ.get("PC_SUPPRESS_WARNINGS")
        ):
            sys.stderr.write(
                "Warning: PC_API_KEY is not set. API calls will likely fail.\n"
            )

    # ─── Synchronous validate ────────────────────────────────────────────

    def validate(self, files, frameworks, options=None):
        """Synchronous validate.

        On a 413 with ``details.suggestedEndpoint='/v1/compliance/scans'``,
        silently falls back to the chunked-session flow so large-repo CI
        jobs don't have to know the difference.
        """
        opts_payload = self._build_options(options)
        try:
            return self._request(
                "POST",
                "/v1/compliance/validate",
                {"files": files, "frameworks": frameworks, "options": opts_payload},
            )
        except ApiError as err:
            if (
                err.status_code == 413
                and err.body
                and err.body.get("error", {})
                .get("details", {})
                .get("suggestedEndpoint")
                == "/v1/compliance/scans"
            ):
                # Server says: this payload won't fit, use chunked sessions
                # instead. Fall back transparently — the caller asked for
                # validate(), the semantics (single scanId with final
                # findings) are preserved.
                return self.validate_chunked(files, frameworks, options)
            raise

    def hook(self, files, frameworks, options=None):
        """Hook endpoint — small per-write call from coding agents.

        No suggestedEndpoint fallback because /hook keeps the historical
        50 MB ceiling; if a single hook write exceeds that, the caller's
        batching is the bug to fix.
        """
        return self._request(
            "POST",
            "/v1/compliance/hook",
            {
                "files": files,
                "frameworks": frameworks,
                "options": self._build_options(options),
            },
        )

    # ─── Chunked sessions ────────────────────────────────────────────────

    def open_session(self, frameworks, options=None):
        """Open a chunked scan session.

        Returns a ``scanId`` that subsequent ``append_chunk`` /
        ``complete_session`` calls reference. Server-side TTL is 30 min
        by default — abandoned sessions self-clean via the
        stale-session reaper.
        """
        return self._request(
            "POST",
            "/v1/compliance/scans",
            {
                "frameworks": frameworks,
                "options": self._build_options(options),
            },
        )

    def append_chunk(self, scan_id, files):
        """Append a chunk of files to an open session.

        Each call has its own /hook-style cap (50 MB / 2000 files). The
        server caches per-content findings, so re-scans of unchanged files
        are O(1).
        """
        return self._request(
            "POST",
            f"/v1/compliance/scans/{urllib.parse.quote(scan_id, safe='')}/chunks",
            {"files": files},
        )

    def complete_session(self, scan_id):
        """Finalize a chunked session.

        Flips status to COMPLETED, computes summary + passed, returns
        final findings.
        """
        return self._request(
            "POST",
            f"/v1/compliance/scans/{urllib.parse.quote(scan_id, safe='')}/complete",
            {},
        )

    def validate_chunked(self, files, frameworks, options=None):
        """High-level helper: open → append (in chunks) → complete.

        Returns the same shape as ``validate()`` so callers that
        auto-fallback don't have to special-case the result.
        """
        options = options or {}
        config = options.get("config") or {}
        chunk_max_bytes = int(config.get("chunkMaxBytes", DEFAULT_CHUNK_MAX_BYTES))
        chunk_max_files = int(config.get("chunkMaxFiles", DEFAULT_CHUNK_MAX_FILES))

        session = self.open_session(frameworks, options)
        scan_id = session["scanId"]

        for chunk in chunk_files(files, chunk_max_bytes, chunk_max_files):
            self.append_chunk(scan_id, chunk)

        result = self.complete_session(scan_id)
        # Preserve the scanId even if the server's complete response doesn't
        # echo it back, so callers always have it in hand.
        if "scanId" not in result:
            result["scanId"] = scan_id
        return result

    # ─── Async validate ──────────────────────────────────────────────────

    def validate_async(self, files, frameworks, options=None):
        """Async-validate: returns a scanId immediately.

        Caller polls ``get_scan(scanId)`` until status is COMPLETED or
        FAILED. Useful for CI runners that don't want to hold a connection
        for a 60 s scan.

        On a 413 with ``details.suggestedEndpoint='/v1/compliance/scans'``,
        transparently falls back to the chunked-session flow — same
        contract as ``validate()``. ``validate_chunked()`` returns the
        full final result rather than a kickoff envelope, so callers
        that branch on ``status='IN_PROGRESS'`` should treat a chunked
        return as a fully-completed scan.
        """
        try:
            return self._request(
                "POST",
                "/v1/compliance/validate?async=true",
                {
                    "files": files,
                    "frameworks": frameworks,
                    "options": self._build_options(options),
                },
            )
        except ApiError as err:
            if (
                err.status_code == 413
                and isinstance(err.body, dict)
                and err.body.get("error", {})
                .get("details", {})
                .get("suggestedEndpoint")
                == "/v1/compliance/scans"
            ):
                return self.validate_chunked(files, frameworks, options)
            raise

    def get_scan(self, scan_id):
        """Fetch the current state of any scan (sync, async, chunked)."""
        return self._request(
            "GET",
            f"/v1/compliance/scans/{urllib.parse.quote(scan_id, safe='')}",
            None,
        )

    def validate_and_poll(self, files, frameworks, options=None):
        """High-level helper: kick off async-validate, poll until terminal.

        Returns the same shape as ``validate()``.
        """
        kickoff = self.validate_async(files, frameworks, options)
        scan_id = kickoff["scanId"]
        # validate_async() may have transparently fallen back to the
        # chunked-session flow on a 413 — in which case `kickoff` is
        # already a fully-completed scan, not just a kickoff envelope.
        # Short-circuit so we don't burn an extra get_scan() round-trip
        # against a scan that's already terminal.
        if kickoff.get("status") in ("COMPLETED", "FAILED", "PASSED"):
            return kickoff
        deadline = time.monotonic() + ASYNC_POLL_TIMEOUT_S

        # Always poll at least once, and re-check the deadline AFTER the
        # blocking get_scan() returns rather than only at loop top — a
        # single stalled get_scan() could otherwise extend wall-clock
        # well past ASYNC_POLL_TIMEOUT_S (a stuck call sleeps up to
        # REQUEST_TIMEOUT_S on its own). Belt-and-suspenders: also check
        # before sleeping so a scan that completes during the trailing
        # sleep window isn't reported as a timeout.
        # Match the terminal-status set used by the short-circuit above
        # — some endpoints/older API responses surface 'PASSED' rather
        # than 'COMPLETED' for a successful scan. Treat all three as
        # terminal so the loop doesn't spin out to the timeout while the
        # scan is actually finished.
        while True:
            scan = self.get_scan(scan_id)
            if scan.get("status") in ("COMPLETED", "FAILED", "PASSED"):
                if "scanId" not in scan:
                    scan["scanId"] = scan_id
                return scan
            if time.monotonic() >= deadline:
                break
            time.sleep(ASYNC_POLL_INTERVAL_S)

        raise Exception(
            f"Async validate scan {scan_id} did not complete within "
            f"{ASYNC_POLL_TIMEOUT_S}s. Re-run with the same scanId to keep "
            f"polling: prodcycle scans {scan_id}"
        )

    # ─── Internals ───────────────────────────────────────────────────────

    def _build_options(self, options):
        options = options or {}
        opts_payload = {
            "severity_threshold": options.get("severityThreshold"),
            "fail_on": options.get("failOn"),
        }
        config = options.get("config")
        if isinstance(config, dict):
            # Strip client-routing keys (mode / chunkMaxBytes / chunkMaxFiles)
            # before forwarding — they steer this SDK, not the server, and
            # leaking them produces 400s on endpoints with strict schemas.
            opts_payload.update(
                {k: v for k, v in config.items() if k not in _CLIENT_ONLY_CONFIG_KEYS}
            )
        # Drop None values — server treats absent + null differently for
        # some keys (severity_threshold default is 'low'; absent uses
        # the workspace default).
        return {k: v for k, v in opts_payload.items() if v is not None}

    def _request(self, method, endpoint, data):
        """Single HTTP request with auth, retry, and structured errors."""
        url = f"{self.api_url}{endpoint}"
        last_error = None

        for attempt in range(MAX_RETRY_ATTEMPTS):
            req = urllib.request.Request(url, method=method)
            req.add_header("Authorization", f"Bearer {self.api_key}")
            if method == "POST":
                req.add_header("Content-Type", "application/json")

            payload = json.dumps(data).encode("utf-8") if data is not None else None

            try:
                with urllib.request.urlopen(
                    req, data=payload, timeout=REQUEST_TIMEOUT_S
                ) as response:
                    body = response.read().decode("utf-8")
                    parsed = json.loads(body) if body else {}
                    return _unwrap_envelope(parsed)
            except urllib.error.HTTPError as err:
                err_body_raw = ""
                try:
                    err_body_raw = err.read().decode("utf-8")
                except Exception:
                    pass
                try:
                    err_body = json.loads(err_body_raw) if err_body_raw else None
                except Exception:
                    err_body = None

                retry_after = _parse_retry_after(err.headers.get("Retry-After"))
                message = (
                    (err_body or {}).get("error", {}).get("message")
                    or f"API request failed with status {err.code}"
                )

                is_retryable = err.code in (429, 503)
                if is_retryable and attempt < MAX_RETRY_ATTEMPTS - 1:
                    delay = (
                        retry_after
                        if retry_after is not None
                        else math.ceil(_retry_backoff_ms(attempt) / 1000)
                    )
                    time.sleep(min(delay, MAX_RETRY_AFTER_SECONDS))
                    continue

                raise ApiError(err.code, err_body, retry_after, message)
            except urllib.error.URLError as err:
                # Connection-level failures (DNS, TCP, TLS). Retryable
                # up to the same cap as 503 — the server may be
                # momentarily down or the network blip may resolve.
                last_error = err
                if attempt < MAX_RETRY_ATTEMPTS - 1:
                    time.sleep(_retry_backoff_ms(attempt) / 1000.0)
                    continue
                raise Exception(
                    f"Failed to connect to ProdCycle API: {err.reason}"
                )

        # Unreachable in practice: every iteration returns, raises, or
        # continues. Kept solely so static analysis can tell that the
        # function always returns or raises (mypy / type-checkers).
        raise AssertionError(  # pragma: no cover
            f"_request loop exited without returning or raising "
            f"(last_error={last_error})"
        )


# ─── Helpers ─────────────────────────────────────────────────────────────


def _unwrap_envelope(parsed):
    """Unwrap ``{status, statusCode, data}`` envelope if present.

    Older/local deployments may return the bare body — fall through in
    that case.
    """
    if (
        isinstance(parsed, dict)
        and "data" in parsed
        and isinstance(parsed.get("data"), dict)
        and "status" in parsed
    ):
        return parsed["data"]
    return parsed


def _retry_backoff_ms(attempt):
    """Exponential backoff with jitter (1s, 2s, 4s, 8s, ...)."""
    base = 1000 * (2 ** attempt)
    jitter = random.random() * 500
    return base + jitter


def _parse_retry_after(value):
    """Parse Retry-After header. Returns seconds (int) or None."""
    if not value:
        return None
    try:
        return max(0, int(value))
    except ValueError:
        pass
    # HTTP-date form: 'Sun, 06 Nov 1994 08:49:37 GMT'
    try:
        from email.utils import parsedate_to_datetime

        dt = parsedate_to_datetime(value)
        return max(0, math.ceil(dt.timestamp() - time.time()))
    except Exception:
        return None


def chunk_files(files, max_bytes, max_files):
    """Split ``{path: content}`` into chunks under both byte + file caps.

    UTF-8 byte-length is used since the server counts the request body's
    bytes after JSON serialisation; this is a conservative client-side
    approximation.
    """
    chunks = []
    current = {}
    current_bytes = 0
    current_count = 0

    for file_path, content in files.items():
        file_bytes = len(content.encode("utf-8")) + len(file_path.encode("utf-8"))
        # Single file exceeds the cap on its own — emit it as its own
        # chunk and let the server's per-file cap reject if needed.
        # Common case: huge SQL dumps, generated bundles.
        if file_bytes > max_bytes:
            if current_count > 0:
                chunks.append(current)
                current = {}
                current_bytes = 0
                current_count = 0
            chunks.append({file_path: content})
            continue
        if (
            current_bytes + file_bytes > max_bytes
            or current_count + 1 > max_files
        ):
            chunks.append(current)
            current = {}
            current_bytes = 0
            current_count = 0
        current[file_path] = content
        current_bytes += file_bytes
        current_count += 1

    if current_count > 0:
        chunks.append(current)

    return chunks
