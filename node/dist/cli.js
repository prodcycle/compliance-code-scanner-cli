#!/usr/bin/env node
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
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const commander_1 = require("commander");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const index_1 = require("./index");
const table_1 = require("./formatters/table");
const sarif_1 = require("./formatters/sarif");
const prompt_1 = require("./formatters/prompt");
const KNOWN_COMMANDS = new Set([
    'scan',
    'scans',
    'gate',
    'hook',
    'init',
    'help',
    '--help',
    '-h',
    '--version',
    '-V',
]);
/**
 * Back-compat shim: `prodcycle .` used to scan the current directory with no
 * subcommand. Preserve that behavior by injecting `scan` when the first arg
 * isn't a known subcommand or a global flag.
 */
function injectScanDefault(argv) {
    const args = argv.slice(2);
    if (args.length === 0)
        return [...argv.slice(0, 2), 'scan'];
    if (KNOWN_COMMANDS.has(args[0]))
        return argv;
    return [...argv.slice(0, 2), 'scan', ...args];
}
function renderReport(response, format) {
    switch (format) {
        case 'json':
            return JSON.stringify(response, null, 2);
        case 'sarif':
            return JSON.stringify((0, sarif_1.formatSarif)(response), null, 2);
        case 'prompt':
            return (0, prompt_1.formatPrompt)(response);
        case 'table':
        default:
            return (0, table_1.formatTable)(response);
    }
}
function writeOutput(text, outFile) {
    if (outFile) {
        fs.writeFileSync(outFile, text);
    }
    else {
        process.stdout.write(text.endsWith('\n') ? text : text + '\n');
    }
}
function parseList(val) {
    if (!val)
        return undefined;
    return val
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
}
const program = new commander_1.Command();
// Load version from package.json at runtime so CLI --version stays in sync with
// the published package version without requiring a source edit per release.
const PKG_VERSION = (() => {
    try {
        const pkgPath = path.join(__dirname, '..', 'package.json');
        return JSON.parse(fs.readFileSync(pkgPath, 'utf-8')).version ?? '0.0.0';
    }
    catch {
        return '0.0.0';
    }
})();
program
    .name('prodcycle')
    .description('Multi-framework policy-as-code compliance scanner for infrastructure and application code.')
    .version(PKG_VERSION);
// ── scan ────────────────────────────────────────────────────────────────────
program
    .command('scan [repo_path]')
    .description('Scan a repository for compliance violations')
    .option('--framework <ids>', 'Comma-separated framework IDs to evaluate', 'soc2')
    .option('--format <format>', 'Output format: json, sarif, table, prompt', 'table')
    .option('--severity-threshold <severity>', 'Minimum severity to include in report', 'low')
    .option('--fail-on <levels>', 'Comma-separated severities that cause non-zero exit', 'critical,high')
    .option('--include <patterns>', 'Comma-separated glob patterns to include')
    .option('--exclude <patterns>', 'Comma-separated glob patterns to exclude')
    .option('--output <file>', 'Write report to file')
    .option('--api-url <url>', 'Compliance API base URL (or PC_API_URL env)')
    .option('--api-key <key>', 'API key for compliance API (or PC_API_KEY env)')
    .option('--async', 'Use the async-validate flow (server returns 202 immediately; CLI polls until COMPLETED). Useful for large scans where holding a connection isn’t practical.')
    .option('--chunked', 'Force the chunked-session flow regardless of payload size. The default already auto-falls-back to chunked when /validate returns 413 with a chunked-endpoint suggestion.')
    .action(async (repoPath, opts) => {
    try {
        const target = repoPath ?? '.';
        const frameworks = parseList(opts.framework) ?? ['soc2'];
        const failOn = parseList(opts.failOn) ?? ['critical', 'high'];
        const format = (opts.format ?? 'table');
        // --async and --chunked are mutually exclusive; pick the explicit
        // mode if either flag is set, otherwise let `scan()` pick (sync
        // with auto-fallback to chunked on 413).
        let mode = 'sync';
        if (opts.async && opts.chunked) {
            console.error('scan: --async and --chunked are mutually exclusive.');
            process.exit(2);
        }
        if (opts.async)
            mode = 'async';
        else if (opts.chunked)
            mode = 'chunked';
        console.error(`Scanning ${path.resolve(target)} for ${frameworks.join(', ')}` +
            (mode === 'sync' ? '' : ` (${mode} mode)`) +
            '...');
        const response = await (0, index_1.scan)({
            repoPath: target,
            frameworks,
            options: {
                severityThreshold: opts.severityThreshold,
                failOn: failOn,
                include: parseList(opts.include),
                exclude: parseList(opts.exclude),
                apiUrl: opts.apiUrl,
                apiKey: opts.apiKey,
                config: { mode },
            },
        });
        writeOutput(renderReport(response, format), opts.output);
        process.exit(response.exitCode);
    }
    catch (error) {
        console.error(`\u2717 Error: ${error.message}`);
        process.exit(2);
    }
});
// ── gate ────────────────────────────────────────────────────────────────────
program
    .command('gate')
    .description('Evaluate a JSON payload of files from stdin (low-latency hook endpoint)')
    .option('--framework <ids>', 'Comma-separated framework IDs to evaluate', 'soc2')
    .option('--format <format>', 'Output format: json, sarif, table, prompt', 'prompt')
    .option('--output <file>', 'Write report to file')
    .option('--api-url <url>', 'Compliance API base URL (or PC_API_URL env)')
    .option('--api-key <key>', 'API key for compliance API (or PC_API_KEY env)')
    .action(async (opts) => {
    try {
        const frameworks = parseList(opts.framework) ?? ['soc2'];
        const format = (opts.format ?? 'prompt');
        const stdin = await readStdin();
        if (!stdin.trim()) {
            console.error('gate: no input on stdin. Expected JSON payload: {"files": {...}}');
            process.exit(2);
        }
        let payload;
        try {
            payload = JSON.parse(stdin);
        }
        catch (e) {
            console.error(`gate: invalid JSON on stdin: ${e.message}`);
            process.exit(2);
            return;
        }
        if (!payload.files || typeof payload.files !== 'object') {
            console.error('gate: payload must include a "files" object of {path: content}');
            process.exit(2);
            return;
        }
        const response = await (0, index_1.gate)({
            files: payload.files,
            frameworks,
            apiUrl: opts.apiUrl,
            apiKey: opts.apiKey,
        });
        writeOutput(renderReport(response, format), opts.output);
        process.exit(response.exitCode);
    }
    catch (error) {
        console.error(`\u2717 Error: ${error.message}`);
        process.exit(2);
    }
});
// ── scans ───────────────────────────────────────────────────────────────────
// Fetch the current status / final result of any scan by ID. Useful with
// `--async` to resume a poll loop after a CI step boundary, or to inspect
// a chunked session that was abandoned mid-flight.
program
    .command('scans <scanId>')
    .description('Get the status + findings of a scan by ID')
    .option('--format <format>', 'Output format: json, sarif, table, prompt', 'json')
    .option('--output <file>', 'Write report to file')
    .option('--api-url <url>', 'Compliance API base URL (or PC_API_URL env)')
    .option('--api-key <key>', 'API key for compliance API (or PC_API_KEY env)')
    .action(async (scanId, opts) => {
    try {
        const format = (opts.format ?? 'json');
        const { ComplianceApiClient } = await Promise.resolve().then(() => __importStar(require('./api-client')));
        const client = new ComplianceApiClient(opts.apiUrl, opts.apiKey);
        const scan = await client.getScan(scanId);
        const payload = {
            scanId,
            passed: scan.passed,
            status: scan.status ?? 'COMPLETED',
            findings: scan.findings ?? [],
            summary: scan.summary,
            exitCode: scan.passed ? 0 : 1,
        };
        // Use the same renderer as `scan` so format=table/sarif/prompt all work.
        writeOutput(renderReport(payload, format), opts.output);
        // Exit 2 if scan is still in progress — the CLI run shouldn't gate on
        // an indeterminate result.
        if (scan.status === 'IN_PROGRESS') {
            console.error(`Scan ${scanId} is still IN_PROGRESS. Re-run the same command to keep polling, or use 'pc scan --async' to wait for completion.`);
            process.exit(2);
        }
        process.exit(payload.exitCode);
    }
    catch (error) {
        console.error(`✗ Error: ${error.message}`);
        process.exit(2);
    }
});
// ── hook ────────────────────────────────────────────────────────────────────
program
    .command('hook')
    .description('Run as coding-agent post-edit hook (reads stdin or --file)')
    .option('--framework <ids>', 'Comma-separated framework IDs to evaluate', 'soc2')
    .option('--format <format>', 'Output format: json, sarif, table, prompt', 'prompt')
    .option('--file <path>', 'Scan this file from disk (alternative to reading content from stdin)')
    .option('--fail-on <levels>', 'Severities that cause non-zero exit', 'critical,high')
    .option('--output <file>', 'Write report to file')
    .option('--api-url <url>', 'Compliance API base URL (or PC_API_URL env)')
    .option('--api-key <key>', 'API key for compliance API (or PC_API_KEY env)')
    .action(async (opts) => {
    try {
        const frameworks = parseList(opts.framework) ?? ['soc2'];
        const format = (opts.format ?? 'prompt');
        const files = await collectHookFiles(opts.file);
        if (!files || Object.keys(files).length === 0) {
            // No files to check — exit clean so the agent proceeds.
            process.exit(0);
            return;
        }
        const response = await (0, index_1.gate)({
            files,
            frameworks,
            apiUrl: opts.apiUrl,
            apiKey: opts.apiKey,
        });
        writeOutput(renderReport(response, format), opts.output);
        process.exit(response.exitCode);
    }
    catch (error) {
        console.error(`\u2717 Error: ${error.message}`);
        process.exit(2);
    }
});
/**
 * Resolve the files to scan for a `hook` invocation. Supports:
 *   - `--file <path>` — read that file from disk
 *   - stdin: `{"files": {path: content}}` (same as gate)
 *   - stdin: `{"file_path": "...", "content": "..."}` (single file)
 *   - stdin: Claude Code PostToolUse shape —
 *       `{"tool_input": {"file_path": "...", "content"|"new_string": "..."}}`
 *     When only `file_path` is given and we can read the file, we do.
 */
async function collectHookFiles(filePath) {
    if (filePath) {
        const absolute = path.resolve(filePath);
        if (!fs.existsSync(absolute)) {
            console.error(`hook: --file path does not exist: ${absolute}`);
            process.exit(2);
        }
        const content = fs.readFileSync(absolute, 'utf8');
        return { [filePath]: content };
    }
    const stdin = await readStdin();
    if (!stdin.trim()) {
        console.error('hook: no input. Provide --file <path> or JSON on stdin (see `prodcycle hook --help`).');
        process.exit(2);
    }
    let payload;
    try {
        payload = JSON.parse(stdin);
    }
    catch (e) {
        console.error(`hook: invalid JSON on stdin: ${e.message}`);
        process.exit(2);
    }
    // Shape 1: {"files": {path: content}} — gate-compatible
    if (payload && typeof payload.files === 'object' && payload.files !== null) {
        return payload.files;
    }
    // Shape 2: top-level single file. Shape 3: Claude Code tool_input nesting.
    const candidate = payload?.tool_input ?? payload;
    const hookFilePath = candidate?.file_path ?? candidate?.path;
    const hookContent = candidate?.content ?? candidate?.new_string;
    if (hookFilePath && typeof hookContent === 'string') {
        return { [hookFilePath]: hookContent };
    }
    if (hookFilePath && fs.existsSync(hookFilePath)) {
        // Only a path was given — read from disk so post-edit hooks still work
        // when the agent doesn't ship the content inline.
        const content = fs.readFileSync(hookFilePath, 'utf8');
        return { [hookFilePath]: content };
    }
    console.error('hook: stdin payload not recognized. Expected one of:\n' +
        '  {"files": {"path": "content"}}\n' +
        '  {"file_path": "...", "content": "..."}\n' +
        '  {"tool_input": {"file_path": "...", "content": "..."}}');
    process.exit(2);
    return null; // unreachable
}
// ── init ────────────────────────────────────────────────────────────────────
program
    .command('init')
    .description('Configure compliance hooks for coding agents')
    .option('--agent <agents>', 'Comma-separated agents to configure (claude, cursor, codex, opencode, github-copilot, gemini-cli). Use "all" to configure every agent. Default: auto-detect.')
    .option('--force', 'Overwrite existing compliance hook entries')
    .option('--dir <path>', 'Project directory to configure', '.')
    .action((opts) => {
    try {
        const dir = path.resolve(opts.dir ?? '.');
        const agents = resolveAgents(opts.agent, dir);
        if (agents.length === 0) {
            console.error('init: no agents selected and none auto-detected. ' +
                'Use --agent <name> to configure explicitly (claude, cursor, codex, ' +
                'opencode, github-copilot, gemini-cli, or "all").');
            process.exit(2);
        }
        let anyFailed = false;
        const writtenPaths = new Set();
        for (const agent of agents) {
            const result = configureAgent(agent, dir, !!opts.force, writtenPaths);
            process.stdout.write(result.message + '\n');
            if (result.status === 'failed')
                anyFailed = true;
        }
        process.exit(anyFailed ? 1 : 0);
    }
    catch (error) {
        console.error(`\u2717 Error: ${error.message}`);
        process.exit(2);
    }
});
const ALL_AGENTS = [
    'claude',
    'cursor',
    'codex',
    'opencode',
    'github-copilot',
    'gemini-cli',
];
function isAgentName(name) {
    return ALL_AGENTS.includes(name);
}
function resolveAgents(userChoice, dir) {
    if (userChoice) {
        const list = parseList(userChoice) ?? [];
        if (list.length === 1 && list[0] === 'all')
            return ALL_AGENTS.slice();
        const valid = [];
        for (const name of list) {
            if (isAgentName(name))
                valid.push(name);
            else
                console.error(`init: unknown agent "${name}" — ignoring`);
        }
        return valid;
    }
    // Auto-detect: look for config dirs/files that indicate the agent is already in use.
    const detected = [];
    if (fs.existsSync(path.join(dir, '.claude')))
        detected.push('claude');
    if (fs.existsSync(path.join(dir, '.cursor')))
        detected.push('cursor');
    if (fs.existsSync(path.join(dir, '.codex')))
        detected.push('codex');
    if (fs.existsSync(path.join(dir, '.opencode')))
        detected.push('opencode');
    if (fs.existsSync(path.join(dir, '.github', 'copilot-instructions.md'))) {
        detected.push('github-copilot');
    }
    if (fs.existsSync(path.join(dir, 'GEMINI.md')) ||
        fs.existsSync(path.join(dir, '.gemini'))) {
        detected.push('gemini-cli');
    }
    return detected;
}
function configureAgent(agent, dir, force, writtenPaths) {
    switch (agent) {
        case 'claude':
            return configureClaudeCode(dir, force);
        case 'cursor':
            return configureCursor(dir, force);
        case 'codex':
            return configureInstructionFile(agent, dir, 'AGENTS.md', force, writtenPaths);
        case 'opencode':
            return configureInstructionFile(agent, dir, 'AGENTS.md', force, writtenPaths);
        case 'github-copilot':
            return configureInstructionFile(agent, dir, path.join('.github', 'copilot-instructions.md'), force, writtenPaths);
        case 'gemini-cli':
            return configureInstructionFile(agent, dir, 'GEMINI.md', force, writtenPaths);
    }
}
const CLAUDE_MATCHER = 'Write|Edit|MultiEdit';
const CLAUDE_COMMAND = 'prodcycle hook';
function configureClaudeCode(dir, force) {
    const claudeDir = path.join(dir, '.claude');
    const settingsPath = path.join(claudeDir, 'settings.json');
    let settings = {};
    if (fs.existsSync(settingsPath)) {
        try {
            settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
            if (typeof settings !== 'object' || settings === null || Array.isArray(settings)) {
                return {
                    status: 'failed',
                    message: `[claude] ${settingsPath} is not a JSON object — refusing to overwrite. Fix the file manually.`,
                };
            }
        }
        catch (e) {
            return {
                status: 'failed',
                message: `[claude] could not parse ${settingsPath}: ${e.message}. Fix the file manually.`,
            };
        }
    }
    const hooks = (settings.hooks ??= {});
    const postToolUse = (hooks.PostToolUse ??= []);
    // Look for an existing prodcycle entry
    const existing = postToolUse.find((b) => b.hooks?.some((h) => h.type === 'command' && h.command.trim().startsWith('prodcycle hook')));
    if (existing && !force) {
        return {
            status: 'already',
            message: `[claude] PostToolUse hook for prodcycle already present in ${settingsPath}. Use --force to rewrite.`,
        };
    }
    if (existing && force) {
        // Replace in place — preserve the matcher, rewrite the command to the canonical form
        existing.matcher = CLAUDE_MATCHER;
        existing.hooks = [{ type: 'command', command: CLAUDE_COMMAND }];
    }
    else {
        postToolUse.push({
            matcher: CLAUDE_MATCHER,
            hooks: [{ type: 'command', command: CLAUDE_COMMAND }],
        });
    }
    if (!fs.existsSync(claudeDir))
        fs.mkdirSync(claudeDir, { recursive: true });
    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n');
    return {
        status: 'installed',
        message: `[claude] wrote PostToolUse hook to ${settingsPath}. Requires PC_API_KEY in the environment when Claude Code runs.`,
    };
}
const CURSOR_COMMAND = 'prodcycle hook';
function configureCursor(dir, force) {
    const cursorDir = path.join(dir, '.cursor');
    const hooksPath = path.join(cursorDir, 'hooks.json');
    let config = { version: 1 };
    if (fs.existsSync(hooksPath)) {
        try {
            const parsed = JSON.parse(fs.readFileSync(hooksPath, 'utf8'));
            if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
                return {
                    status: 'failed',
                    message: `[cursor] ${hooksPath} is not a JSON object — refusing to overwrite. Fix the file manually.`,
                };
            }
            config = parsed;
        }
        catch (e) {
            return {
                status: 'failed',
                message: `[cursor] could not parse ${hooksPath}: ${e.message}. Fix the file manually.`,
            };
        }
    }
    if (typeof config.version !== 'number')
        config.version = 1;
    const hooks = (config.hooks ??= {});
    const afterFileEdit = (hooks.afterFileEdit ??= []);
    const existing = afterFileEdit.find((h) => typeof h.command === 'string' && h.command.trim().startsWith('prodcycle hook'));
    if (existing && !force) {
        return {
            status: 'already',
            message: `[cursor] afterFileEdit hook for prodcycle already present in ${hooksPath}. Use --force to rewrite.`,
        };
    }
    if (existing && force) {
        existing.command = CURSOR_COMMAND;
    }
    else {
        afterFileEdit.push({ command: CURSOR_COMMAND });
    }
    if (!fs.existsSync(cursorDir))
        fs.mkdirSync(cursorDir, { recursive: true });
    fs.writeFileSync(hooksPath, JSON.stringify(config, null, 2) + '\n');
    return {
        status: 'installed',
        message: `[cursor] wrote afterFileEdit hook to ${hooksPath}. Requires PC_API_KEY in the environment when Cursor runs.`,
    };
}
// ── Instruction-file agents (codex, opencode, github-copilot, gemini-cli) ───
const INSTRUCTION_BEGIN = '<!-- prodcycle:begin -->';
const INSTRUCTION_END = '<!-- prodcycle:end -->';
function buildInstructionBlock() {
    return [
        INSTRUCTION_BEGIN,
        '## ProdCycle Compliance',
        '',
        'This project enforces SOC 2, HIPAA, and NIST CSF policies on infrastructure',
        'and application code. After creating or modifying any file, run the compliance',
        'scanner and fix every violation before continuing:',
        '',
        '```bash',
        'npx prodcycle scan . --format prompt',
        '```',
        '',
        'Each finding includes a severity, rule ID, message, and remediation guidance.',
        'Apply the fixes, then re-run the scan until every check passes.',
        INSTRUCTION_END,
        '',
    ].join('\n');
}
function configureInstructionFile(agent, dir, relPath, force, writtenPaths) {
    const fullPath = path.join(dir, relPath);
    // Multiple agents may share the same target file (codex + opencode → AGENTS.md).
    // Skip the second agent silently if we already wrote to the same file in this run.
    if (writtenPaths.has(fullPath)) {
        return {
            status: 'already',
            message: `[${agent}] ${relPath} already written in this run (shared with another agent).`,
        };
    }
    let existing = '';
    if (fs.existsSync(fullPath)) {
        existing = fs.readFileSync(fullPath, 'utf8');
    }
    const block = buildInstructionBlock();
    const hasBlock = existing.includes(INSTRUCTION_BEGIN) && existing.includes(INSTRUCTION_END);
    if (hasBlock && !force) {
        return {
            status: 'already',
            message: `[${agent}] prodcycle instruction block already present in ${fullPath}. Use --force to rewrite.`,
        };
    }
    let next;
    if (hasBlock) {
        const pattern = new RegExp(`${escapeRegExp(INSTRUCTION_BEGIN)}[\\s\\S]*?${escapeRegExp(INSTRUCTION_END)}\\n?`);
        next = existing.replace(pattern, block);
    }
    else if (existing.trim().length === 0) {
        next = block;
    }
    else {
        next = existing.replace(/\n*$/, '\n\n') + block;
    }
    const parent = path.dirname(fullPath);
    if (!fs.existsSync(parent))
        fs.mkdirSync(parent, { recursive: true });
    fs.writeFileSync(fullPath, next);
    writtenPaths.add(fullPath);
    return {
        status: 'installed',
        message: `[${agent}] wrote compliance instructions to ${fullPath}.`,
    };
}
function escapeRegExp(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
function readStdin() {
    return new Promise((resolve, reject) => {
        if (process.stdin.isTTY) {
            resolve('');
            return;
        }
        const chunks = [];
        process.stdin.on('data', (c) => chunks.push(c));
        process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        process.stdin.on('error', reject);
    });
}
program.parse(injectScanDefault(process.argv));
