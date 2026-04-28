"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.scan = scan;
exports.gate = gate;
const api_client_1 = require("./api-client");
const fs_1 = require("./utils/fs");
__exportStar(require("./api-client"), exports);
__exportStar(require("./formatters/table"), exports);
__exportStar(require("./formatters/prompt"), exports);
__exportStar(require("./formatters/sarif"), exports);
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
async function scan(params) {
    const { repoPath, frameworks = ['soc2'], options = {} } = params;
    const files = await (0, fs_1.collectFiles)(repoPath, options.include, options.exclude);
    if (Object.keys(files).length === 0) {
        return {
            passed: true,
            exitCode: 0,
            findings: [],
            report: null,
            summary: undefined,
        };
    }
    const client = new api_client_1.ComplianceApiClient(options.apiUrl, options.apiKey);
    const mode = options.config?.mode ?? 'sync';
    let response;
    if (mode === 'async') {
        response = await client.validateAndPoll(files, frameworks, options);
    }
    else if (mode === 'chunked') {
        response = await client.validateChunked(files, frameworks, options);
    }
    else {
        response = await client.validate(files, frameworks, options);
    }
    return {
        scanId: response.scanId,
        passed: response.passed,
        exitCode: response.passed ? 0 : 1,
        findings: response.findings ?? [],
        report: response.report ?? null,
        summary: response.summary,
    };
}
/**
 * Gate code strings directly without writing to disk (low-latency hook
 * endpoint, used by coding-agent post-edit hooks).
 */
async function gate(options) {
    const { files, frameworks = ['soc2'], ...scanOpts } = options;
    const client = new api_client_1.ComplianceApiClient(options.apiUrl, options.apiKey);
    const response = await client.hook(files, frameworks, scanOpts);
    return {
        passed: response.passed,
        exitCode: response.passed ? 0 : 1,
        findings: response.findings ?? [],
        prompt: response.prompt,
        summary: response.summary,
    };
}
