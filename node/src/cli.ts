#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import { scan, gate } from './index';
import { formatTable } from './formatters/table';
import { formatSarif } from './formatters/sarif';
import { formatPrompt } from './formatters/prompt';

type Format = 'json' | 'sarif' | 'table' | 'prompt';

const KNOWN_COMMANDS = new Set([
  'scan',
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
function injectScanDefault(argv: string[]): string[] {
  const args = argv.slice(2);
  if (args.length === 0) return [...argv.slice(0, 2), 'scan'];
  if (KNOWN_COMMANDS.has(args[0])) return argv;
  return [...argv.slice(0, 2), 'scan', ...args];
}

function renderReport(response: unknown, format: Format): string {
  switch (format) {
    case 'json':
      return JSON.stringify(response, null, 2);
    case 'sarif':
      return JSON.stringify(formatSarif(response), null, 2);
    case 'prompt':
      return formatPrompt(response);
    case 'table':
    default:
      return formatTable(response);
  }
}

function writeOutput(text: string, outFile?: string): void {
  if (outFile) {
    fs.writeFileSync(outFile, text);
  } else {
    process.stdout.write(text.endsWith('\n') ? text : text + '\n');
  }
}

function parseList(val?: string): string[] | undefined {
  if (!val) return undefined;
  return val
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

const program = new Command();

program
  .name('prodcycle')
  .description(
    'Multi-framework policy-as-code compliance scanner for infrastructure and application code.',
  )
  .version('0.3.0');

// ── scan ────────────────────────────────────────────────────────────────────
program
  .command('scan [repo_path]')
  .description('Scan a repository for compliance violations')
  .option('--framework <ids>', 'Comma-separated framework IDs to evaluate', 'soc2')
  .option('--format <format>', 'Output format: json, sarif, table, prompt', 'table')
  .option('--severity-threshold <severity>', 'Minimum severity to include in report', 'low')
  .option(
    '--fail-on <levels>',
    'Comma-separated severities that cause non-zero exit',
    'critical,high',
  )
  .option('--include <patterns>', 'Comma-separated glob patterns to include')
  .option('--exclude <patterns>', 'Comma-separated glob patterns to exclude')
  .option('--output <file>', 'Write report to file')
  .option('--api-url <url>', 'Compliance API base URL (or PC_API_URL env)')
  .option('--api-key <key>', 'API key for compliance API (or PC_API_KEY env)')
  .action(async (repoPath: string | undefined, opts: Record<string, any>) => {
    try {
      const target = repoPath ?? '.';
      const frameworks = parseList(opts.framework) ?? ['soc2'];
      const failOn = parseList(opts.failOn) ?? ['critical', 'high'];
      const format = (opts.format ?? 'table') as Format;

      console.error(`Scanning ${path.resolve(target)} for ${frameworks.join(', ')}...`);

      const response = await scan({
        repoPath: target,
        frameworks,
        options: {
          severityThreshold: opts.severityThreshold,
          failOn: failOn as any,
          include: parseList(opts.include),
          exclude: parseList(opts.exclude),
          apiUrl: opts.apiUrl,
          apiKey: opts.apiKey,
        },
      });

      writeOutput(renderReport(response, format), opts.output);
      process.exit(response.exitCode);
    } catch (error: any) {
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
  .action(async (opts: Record<string, any>) => {
    try {
      const frameworks = parseList(opts.framework) ?? ['soc2'];
      const format = (opts.format ?? 'prompt') as Format;

      const stdin = await readStdin();
      if (!stdin.trim()) {
        console.error('gate: no input on stdin. Expected JSON payload: {"files": {...}}');
        process.exit(2);
      }

      let payload: { files?: Record<string, string> };
      try {
        payload = JSON.parse(stdin);
      } catch (e: any) {
        console.error(`gate: invalid JSON on stdin: ${e.message}`);
        process.exit(2);
        return;
      }

      if (!payload.files || typeof payload.files !== 'object') {
        console.error('gate: payload must include a "files" object of {path: content}');
        process.exit(2);
        return;
      }

      const response = await gate({
        files: payload.files,
        frameworks,
        apiUrl: opts.apiUrl,
        apiKey: opts.apiKey,
      });

      writeOutput(renderReport(response, format), opts.output);
      process.exit(response.exitCode);
    } catch (error: any) {
      console.error(`\u2717 Error: ${error.message}`);
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
  .action(async (opts: Record<string, any>) => {
    try {
      const frameworks = parseList(opts.framework) ?? ['soc2'];
      const format = (opts.format ?? 'prompt') as Format;

      const files = await collectHookFiles(opts.file);
      if (!files || Object.keys(files).length === 0) {
        // No files to check — exit clean so the agent proceeds.
        process.exit(0);
        return;
      }

      const response = await gate({
        files,
        frameworks,
        apiUrl: opts.apiUrl,
        apiKey: opts.apiKey,
      });

      writeOutput(renderReport(response, format), opts.output);
      process.exit(response.exitCode);
    } catch (error: any) {
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
async function collectHookFiles(
  filePath: string | undefined,
): Promise<Record<string, string> | null> {
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
    console.error(
      'hook: no input. Provide --file <path> or JSON on stdin (see `prodcycle hook --help`).',
    );
    process.exit(2);
  }

  let payload: any;
  try {
    payload = JSON.parse(stdin);
  } catch (e: any) {
    console.error(`hook: invalid JSON on stdin: ${e.message}`);
    process.exit(2);
  }

  // Shape 1: {"files": {path: content}} — gate-compatible
  if (payload && typeof payload.files === 'object' && payload.files !== null) {
    return payload.files;
  }

  // Shape 2: top-level single file. Shape 3: Claude Code tool_input nesting.
  const candidate = payload?.tool_input ?? payload;
  const hookFilePath: string | undefined = candidate?.file_path ?? candidate?.path;
  const hookContent: string | undefined = candidate?.content ?? candidate?.new_string;

  if (hookFilePath && typeof hookContent === 'string') {
    return { [hookFilePath]: hookContent };
  }

  if (hookFilePath && fs.existsSync(hookFilePath)) {
    // Only a path was given — read from disk so post-edit hooks still work
    // when the agent doesn't ship the content inline.
    const content = fs.readFileSync(hookFilePath, 'utf8');
    return { [hookFilePath]: content };
  }

  console.error(
    'hook: stdin payload not recognized. Expected one of:\n' +
      '  {"files": {"path": "content"}}\n' +
      '  {"file_path": "...", "content": "..."}\n' +
      '  {"tool_input": {"file_path": "...", "content": "..."}}',
  );
  process.exit(2);
  return null; // unreachable
}

// ── init ────────────────────────────────────────────────────────────────────
program
  .command('init')
  .description('Configure compliance hooks for coding agents')
  .option(
    '--agent <agents>',
    'Comma-separated agents to configure (claude, cursor). Default: auto-detect.',
  )
  .option('--force', 'Overwrite existing compliance hook entries')
  .option('--dir <path>', 'Project directory to configure', '.')
  .action((opts: Record<string, any>) => {
    try {
      const dir = path.resolve(opts.dir ?? '.');
      const agents = resolveAgents(opts.agent, dir);

      if (agents.length === 0) {
        console.error(
          'init: no agents selected and none auto-detected. ' +
            'Use --agent claude (or cursor) to configure explicitly.',
        );
        process.exit(2);
      }

      let anyFailed = false;
      for (const agent of agents) {
        const result = configureAgent(agent, dir, !!opts.force);
        process.stdout.write(result.message + '\n');
        if (result.status === 'failed') anyFailed = true;
      }
      process.exit(anyFailed ? 1 : 0);
    } catch (error: any) {
      console.error(`\u2717 Error: ${error.message}`);
      process.exit(2);
    }
  });

type AgentName = 'claude' | 'cursor';

function resolveAgents(userChoice: string | undefined, dir: string): AgentName[] {
  if (userChoice) {
    const list = parseList(userChoice) ?? [];
    const valid: AgentName[] = [];
    for (const name of list) {
      if (name === 'claude' || name === 'cursor') valid.push(name);
      else console.error(`init: unknown agent "${name}" — ignoring`);
    }
    return valid;
  }

  // Auto-detect
  const detected: AgentName[] = [];
  if (fs.existsSync(path.join(dir, '.claude'))) detected.push('claude');
  if (fs.existsSync(path.join(dir, '.cursor'))) detected.push('cursor');
  return detected;
}

type InitResult = { status: 'installed' | 'already' | 'failed'; message: string };

function configureAgent(agent: AgentName, dir: string, force: boolean): InitResult {
  switch (agent) {
    case 'claude':
      return configureClaudeCode(dir, force);
    case 'cursor':
      return {
        status: 'failed',
        message:
          '[cursor] skipped — Cursor does not currently expose a post-edit hook mechanism.\n' +
          '         Add a `.cursor/rules` entry pointing reviewers at `prodcycle scan .` until hook support lands.',
      };
  }
}

interface ClaudeHookEntry {
  type: 'command';
  command: string;
}

interface ClaudeMatcherBlock {
  matcher?: string;
  hooks?: ClaudeHookEntry[];
}

interface ClaudeSettings {
  hooks?: {
    PostToolUse?: ClaudeMatcherBlock[];
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

const CLAUDE_MATCHER = 'Write|Edit|MultiEdit';
const CLAUDE_COMMAND = 'prodcycle hook';

function configureClaudeCode(dir: string, force: boolean): InitResult {
  const claudeDir = path.join(dir, '.claude');
  const settingsPath = path.join(claudeDir, 'settings.json');

  let settings: ClaudeSettings = {};
  if (fs.existsSync(settingsPath)) {
    try {
      settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8')) as ClaudeSettings;
      if (typeof settings !== 'object' || settings === null || Array.isArray(settings)) {
        return {
          status: 'failed',
          message: `[claude] ${settingsPath} is not a JSON object — refusing to overwrite. Fix the file manually.`,
        };
      }
    } catch (e: any) {
      return {
        status: 'failed',
        message: `[claude] could not parse ${settingsPath}: ${e.message}. Fix the file manually.`,
      };
    }
  }

  const hooks = (settings.hooks ??= {});
  const postToolUse = (hooks.PostToolUse ??= []);

  // Look for an existing prodcycle entry
  const existing = postToolUse.find((b) =>
    b.hooks?.some((h) => h.type === 'command' && h.command.trim().startsWith('prodcycle hook')),
  );

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
  } else {
    postToolUse.push({
      matcher: CLAUDE_MATCHER,
      hooks: [{ type: 'command', command: CLAUDE_COMMAND }],
    });
  }

  if (!fs.existsSync(claudeDir)) fs.mkdirSync(claudeDir, { recursive: true });
  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n');

  return {
    status: 'installed',
    message: `[claude] wrote PostToolUse hook to ${settingsPath}. Requires PC_API_KEY in the environment when Claude Code runs.`,
  };
}

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    if (process.stdin.isTTY) {
      resolve('');
      return;
    }
    const chunks: Buffer[] = [];
    process.stdin.on('data', (c) => chunks.push(c));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
  });
}

program.parse(injectScanDefault(process.argv));
