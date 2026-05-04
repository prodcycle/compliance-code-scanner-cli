import argparse
import json
import os
import subprocess
import sys

from prodcycle import scan, gate, __version__
from prodcycle.formatters.table import format_table
from prodcycle.formatters.sarif import format_sarif
from prodcycle.formatters.prompt import format_prompt

KNOWN_COMMANDS = {'scan', 'scans', 'gate', 'hook', 'init', 'help', '--help', '-h', '--version', '-V'}


def _inject_scan_default(argv):
    """Back-compat: `prodcycle .` used to scan the current directory with no
    subcommand. Preserve that behavior by injecting `scan` when the first arg
    isn't a known subcommand or a global flag."""
    args = argv[1:]
    if not args:
        return [argv[0], 'scan']
    if args[0] in KNOWN_COMMANDS:
        return argv
    return [argv[0], 'scan', *args]


def _parse_list(val):
    if not val:
        return None
    return [s.strip() for s in val.split(',') if s.strip()]


def _render(response, fmt):
    if fmt == 'json':
        return json.dumps(response, indent=2, default=str)
    if fmt == 'sarif':
        return json.dumps(format_sarif(response), indent=2, default=str)
    if fmt == 'prompt':
        return format_prompt(response)
    return format_table(response)


def _write_output(text, out_file):
    if out_file:
        with open(out_file, 'w') as f:
            f.write(text)
    else:
        if not text.endswith('\n'):
            text = text + '\n'
        sys.stdout.write(text)


def _compute_changed_files(repo_path, pr_range):
    """Return files changed in `git diff --name-only --diff-filter=ACMR <range>`,
    relative to the git repo root. Filters out deletions so the scanner doesn't
    chase paths that no longer exist on disk.
    """
    try:
        result = subprocess.run(
            ['git', '-C', repo_path, 'diff', '--name-only', '--diff-filter=ACMR', pr_range],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or '').strip() or str(e)
        print(f'--pr: git diff failed for range "{pr_range}": {stderr}', file=sys.stderr)
        sys.exit(2)
    except FileNotFoundError:
        print('--pr: git executable not found in PATH', file=sys.stderr)
        sys.exit(2)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _add_common_scan_args(parser):
    parser.add_argument('--framework', default='soc2', help='Comma-separated framework IDs to evaluate')
    parser.add_argument('--format', default='table', help='Output format: json, sarif, table, prompt')
    parser.add_argument('--severity-threshold', default='low', help='Minimum severity to include in report')
    parser.add_argument('--fail-on', default='critical,high', help='Comma-separated severities that cause non-zero exit')
    parser.add_argument('--include', help='Comma-separated glob patterns to include')
    parser.add_argument('--exclude', help='Comma-separated glob patterns to exclude')
    parser.add_argument('--output', help='Write report to file')
    parser.add_argument('--api-url', help='Compliance API base URL (or PC_API_URL env)')
    parser.add_argument('--api-key', help='API key for compliance API (or PC_API_KEY env)')
    # --async / --chunked select the scan submission mode. Default is sync
    # with auto-fallback to chunked on 413 (the server tells us via
    # error.details.suggestedEndpoint when /validate is too small).
    parser.add_argument(
        '--async',
        action='store_true',
        dest='use_async',
        help='Use async-validate (server returns 202 immediately; CLI polls until COMPLETED). Useful for large scans where holding a connection isn\'t practical.',
    )
    parser.add_argument(
        '--chunked',
        action='store_true',
        dest='use_chunked',
        help='Force the chunked-session flow regardless of payload size. Default already auto-falls-back to chunked when /validate returns 413.',
    )
    parser.add_argument(
        '--pr',
        dest='pr_range',
        help=(
            'Scan only files changed in a git diff range (e.g. "origin/main..HEAD"). '
            'Cuts CI scan time on large repos by skipping unchanged files. '
            'Requires repo_path to be the git repo root.'
        ),
    )


def _cmd_scan(args):
    repo_path = args.repo_path or '.'
    frameworks = _parse_list(args.framework) or ['soc2']
    fail_on = _parse_list(args.fail_on) or ['critical', 'high']
    fmt = args.format or 'table'

    if args.use_async and args.use_chunked:
        print('scan: --async and --chunked are mutually exclusive.', file=sys.stderr)
        sys.exit(2)
    if args.use_async:
        mode = 'async'
    elif args.use_chunked:
        mode = 'chunked'
    else:
        mode = 'sync'

    # --pr: restrict the scan to files in `git diff --name-only <range>`.
    # Empty diff → exit 0 immediately (nothing to scan).
    include = _parse_list(args.include)
    if args.pr_range:
        changed = _compute_changed_files(repo_path, args.pr_range)
        if not changed:
            print(
                f'No files changed in range "{args.pr_range}". Nothing to scan.',
                file=sys.stderr,
            )
            sys.exit(0)
        print(
            f'--pr {args.pr_range}: restricting scan to {len(changed)} changed file(s).',
            file=sys.stderr,
        )
        include = changed

    suffix = '' if mode == 'sync' else f' ({mode} mode)'
    print(
        f"Scanning {os.path.abspath(repo_path)} for {', '.join(frameworks)}{suffix}...",
        file=sys.stderr,
    )

    response = scan(
        repo_path=repo_path,
        frameworks=frameworks,
        options={
            'severityThreshold': args.severity_threshold,
            'failOn': fail_on,
            'include': include,
            'exclude': _parse_list(args.exclude),
            'apiUrl': args.api_url,
            'apiKey': args.api_key,
            'config': {'mode': mode},
        },
    )

    _write_output(_render(response, fmt), args.output)
    sys.exit(response.get('exitCode', 1))


def _cmd_scans(args):
    """Fetch the current status + findings of a scan by ID.

    Useful with --async to resume a poll loop after a CI step boundary,
    or to inspect a chunked session that was abandoned mid-flight.
    """
    from .api_client import ComplianceApiClient

    client = ComplianceApiClient(args.api_url, args.api_key)
    scan_data = client.get_scan(args.scan_id)
    fmt = args.format or 'json'

    # Compute exit-code consistently for terminal vs in-progress scans
    # so the JSON output and the process exit-code agree. Previously the
    # JSON wrote `exitCode: 1` (compliance failure) for IN_PROGRESS scans
    # while the process exited with 2 (still polling) — automated CI
    # consumers parsing the JSON would misread the in-progress signal as
    # a compliance failure.
    in_progress = scan_data.get('status') == 'IN_PROGRESS'
    if in_progress:
        exit_code = 2
    else:
        exit_code = 0 if scan_data.get('passed') else 1

    payload = {
        'scanId': args.scan_id,
        'passed': scan_data.get('passed', False),
        'status': scan_data.get('status', 'COMPLETED'),
        'findings': scan_data.get('findings', []),
        'summary': scan_data.get('summary', {}),
        'exitCode': exit_code,
    }

    _write_output(_render(payload, fmt), args.output)

    if in_progress:
        print(
            f"Scan {args.scan_id} is still IN_PROGRESS. Re-run the same command "
            f"to keep polling, or use 'prodcycle scan --async' to wait for "
            f"completion.",
            file=sys.stderr,
        )

    sys.exit(exit_code)


def _cmd_gate(args):
    frameworks = _parse_list(args.framework) or ['soc2']
    fmt = args.format or 'prompt'

    if sys.stdin.isatty():
        print('gate: no input on stdin. Expected JSON payload: {"files": {...}}', file=sys.stderr)
        sys.exit(2)

    raw = sys.stdin.read()
    if not raw.strip():
        print('gate: empty stdin', file=sys.stderr)
        sys.exit(2)

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f'gate: invalid JSON on stdin: {e}', file=sys.stderr)
        sys.exit(2)

    files = payload.get('files') if isinstance(payload, dict) else None
    if not isinstance(files, dict):
        print('gate: payload must include a "files" object of {path: content}', file=sys.stderr)
        sys.exit(2)

    response = gate(
        files=files,
        frameworks=frameworks,
        api_url=args.api_url,
        api_key=args.api_key,
    )

    _write_output(_render(response, fmt), args.output)
    sys.exit(response.get('exitCode', 1))


def _collect_hook_files(file_path):
    """Resolve files to scan for a `hook` invocation. Supports:
      --file <path>                                       — read from disk
      stdin: {"files": {path: content}}                   — gate-compatible
      stdin: {"file_path": "...", "content": "..."}       — single file
      stdin: {"tool_input": {"file_path": "...", "content"|"new_string": "..."}}
              — Claude Code PostToolUse shape.
    When only a `file_path` is given and it exists, read from disk.
    """
    if file_path:
        absolute = os.path.abspath(file_path)
        if not os.path.exists(absolute):
            print(f'hook: --file path does not exist: {absolute}', file=sys.stderr)
            sys.exit(2)
        with open(absolute, 'r', encoding='utf-8') as f:
            return {file_path: f.read()}

    if sys.stdin.isatty():
        print(
            'hook: no input. Provide --file <path> or JSON on stdin '
            '(see `prodcycle hook --help`).',
            file=sys.stderr,
        )
        sys.exit(2)

    raw = sys.stdin.read()
    if not raw.strip():
        print('hook: empty stdin', file=sys.stderr)
        sys.exit(2)

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f'hook: invalid JSON on stdin: {e}', file=sys.stderr)
        sys.exit(2)

    if isinstance(payload, dict) and isinstance(payload.get('files'), dict):
        return payload['files']

    candidate = (payload or {}).get('tool_input') if isinstance(payload, dict) else None
    if not isinstance(candidate, dict):
        candidate = payload if isinstance(payload, dict) else {}

    hook_path = candidate.get('file_path') or candidate.get('path')
    hook_content = candidate.get('content')
    if hook_content is None:
        hook_content = candidate.get('new_string')

    if hook_path and isinstance(hook_content, str):
        return {hook_path: hook_content}

    if hook_path and os.path.exists(hook_path):
        with open(hook_path, 'r', encoding='utf-8') as f:
            return {hook_path: f.read()}

    print(
        'hook: stdin payload not recognized. Expected one of:\n'
        '  {"files": {"path": "content"}}\n'
        '  {"file_path": "...", "content": "..."}\n'
        '  {"tool_input": {"file_path": "...", "content": "..."}}',
        file=sys.stderr,
    )
    sys.exit(2)


def _cmd_hook(args):
    frameworks = _parse_list(args.framework) or ['soc2']
    fmt = args.format or 'prompt'

    files = _collect_hook_files(args.file)
    if not files:
        sys.exit(0)

    response = gate(
        files=files,
        frameworks=frameworks,
        api_url=args.api_url,
        api_key=args.api_key,
    )

    _write_output(_render(response, fmt), args.output)
    sys.exit(response.get('exitCode', 1))


CLAUDE_MATCHER = 'Write|Edit|MultiEdit'
CLAUDE_COMMAND = 'prodcycle hook'
CURSOR_COMMAND = 'prodcycle hook'

ALL_AGENTS = ['claude', 'cursor', 'codex', 'opencode', 'github-copilot', 'gemini-cli']

INSTRUCTION_BEGIN = '<!-- prodcycle:begin -->'
INSTRUCTION_END = '<!-- prodcycle:end -->'


def _resolve_agents(user_choice, directory):
    if user_choice:
        parsed = _parse_list(user_choice) or []
        if parsed == ['all']:
            return list(ALL_AGENTS)
        valid = []
        for name in parsed:
            if name in ALL_AGENTS:
                valid.append(name)
            else:
                print(f'init: unknown agent "{name}" — ignoring', file=sys.stderr)
        return valid

    # Auto-detect: look for config dirs/files that indicate the agent is already in use.
    detected = []
    if os.path.exists(os.path.join(directory, '.claude')):
        detected.append('claude')
    if os.path.exists(os.path.join(directory, '.cursor')):
        detected.append('cursor')
    if os.path.exists(os.path.join(directory, '.codex')):
        detected.append('codex')
    if os.path.exists(os.path.join(directory, '.opencode')):
        detected.append('opencode')
    if os.path.exists(os.path.join(directory, '.github', 'copilot-instructions.md')):
        detected.append('github-copilot')
    if (
        os.path.exists(os.path.join(directory, 'GEMINI.md'))
        or os.path.exists(os.path.join(directory, '.gemini'))
    ):
        detected.append('gemini-cli')
    return detected


def _configure_claude(directory, force):
    claude_dir = os.path.join(directory, '.claude')
    settings_path = os.path.join(claude_dir, 'settings.json')

    settings = {}
    if os.path.exists(settings_path):
        try:
            with open(settings_path, 'r', encoding='utf-8') as f:
                settings = json.load(f)
        except json.JSONDecodeError as e:
            return ('failed', f'[claude] could not parse {settings_path}: {e}. Fix the file manually.')
        if not isinstance(settings, dict):
            return ('failed', f'[claude] {settings_path} is not a JSON object — refusing to overwrite.')

    hooks = settings.setdefault('hooks', {})
    post_tool_use = hooks.setdefault('PostToolUse', [])

    existing = None
    for block in post_tool_use:
        if not isinstance(block, dict):
            continue
        for h in block.get('hooks', []) or []:
            if (
                isinstance(h, dict)
                and h.get('type') == 'command'
                and isinstance(h.get('command'), str)
                and h['command'].strip().startswith('prodcycle hook')
            ):
                existing = block
                break
        if existing:
            break

    if existing and not force:
        return (
            'already',
            f'[claude] PostToolUse hook for prodcycle already present in {settings_path}. '
            'Use --force to rewrite.',
        )

    if existing and force:
        existing['matcher'] = CLAUDE_MATCHER
        existing['hooks'] = [{'type': 'command', 'command': CLAUDE_COMMAND}]
    else:
        post_tool_use.append({
            'matcher': CLAUDE_MATCHER,
            'hooks': [{'type': 'command', 'command': CLAUDE_COMMAND}],
        })

    os.makedirs(claude_dir, exist_ok=True)
    with open(settings_path, 'w', encoding='utf-8') as f:
        json.dump(settings, f, indent=2)
        f.write('\n')

    return (
        'installed',
        f'[claude] wrote PostToolUse hook to {settings_path}. '
        'Requires PC_API_KEY in the environment when Claude Code runs.',
    )


def _configure_cursor(directory, force):
    cursor_dir = os.path.join(directory, '.cursor')
    hooks_path = os.path.join(cursor_dir, 'hooks.json')

    config = {'version': 1}
    if os.path.exists(hooks_path):
        try:
            with open(hooks_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except json.JSONDecodeError as e:
            return ('failed', f'[cursor] could not parse {hooks_path}: {e}. Fix the file manually.')
        if not isinstance(config, dict):
            return ('failed', f'[cursor] {hooks_path} is not a JSON object — refusing to overwrite.')

    if not isinstance(config.get('version'), int):
        config['version'] = 1
    hooks = config.setdefault('hooks', {})
    after_file_edit = hooks.setdefault('afterFileEdit', [])

    existing = None
    for h in after_file_edit:
        if (
            isinstance(h, dict)
            and isinstance(h.get('command'), str)
            and h['command'].strip().startswith('prodcycle hook')
        ):
            existing = h
            break

    if existing and not force:
        return (
            'already',
            f'[cursor] afterFileEdit hook for prodcycle already present in {hooks_path}. '
            'Use --force to rewrite.',
        )

    if existing and force:
        existing['command'] = CURSOR_COMMAND
    else:
        after_file_edit.append({'command': CURSOR_COMMAND})

    os.makedirs(cursor_dir, exist_ok=True)
    with open(hooks_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)
        f.write('\n')

    return (
        'installed',
        f'[cursor] wrote afterFileEdit hook to {hooks_path}. '
        'Requires PC_API_KEY in the environment when Cursor runs.',
    )


def _instruction_block():
    return '\n'.join([
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
    ])


def _configure_instruction_file(agent, directory, rel_path, force, written_paths):
    import re

    full_path = os.path.join(directory, rel_path)

    # Multiple agents may share the same target file (codex + opencode → AGENTS.md).
    if full_path in written_paths:
        return (
            'already',
            f'[{agent}] {rel_path} already written in this run (shared with another agent).',
        )

    existing = ''
    if os.path.exists(full_path):
        with open(full_path, 'r', encoding='utf-8') as f:
            existing = f.read()

    block = _instruction_block()
    has_block = INSTRUCTION_BEGIN in existing and INSTRUCTION_END in existing

    if has_block and not force:
        return (
            'already',
            f'[{agent}] prodcycle instruction block already present in {full_path}. '
            'Use --force to rewrite.',
        )

    if has_block:
        pattern = re.compile(
            re.escape(INSTRUCTION_BEGIN) + r'[\s\S]*?' + re.escape(INSTRUCTION_END) + r'\n?'
        )
        next_content = pattern.sub(block, existing)
    elif not existing.strip():
        next_content = block
    else:
        next_content = existing.rstrip('\n') + '\n\n' + block

    parent = os.path.dirname(full_path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)
    with open(full_path, 'w', encoding='utf-8') as f:
        f.write(next_content)
    written_paths.add(full_path)

    return ('installed', f'[{agent}] wrote compliance instructions to {full_path}.')


def _configure_agent(agent, directory, force, written_paths):
    if agent == 'claude':
        return _configure_claude(directory, force)
    if agent == 'cursor':
        return _configure_cursor(directory, force)
    if agent in ('codex', 'opencode'):
        return _configure_instruction_file(agent, directory, 'AGENTS.md', force, written_paths)
    if agent == 'github-copilot':
        return _configure_instruction_file(
            agent, directory, os.path.join('.github', 'copilot-instructions.md'), force, written_paths,
        )
    if agent == 'gemini-cli':
        return _configure_instruction_file(agent, directory, 'GEMINI.md', force, written_paths)
    return ('failed', f'[{agent}] unknown agent')


def _cmd_init(args):
    directory = os.path.abspath(args.dir or '.')
    agents = _resolve_agents(args.agent, directory)

    if not agents:
        print(
            'init: no agents selected and none auto-detected. '
            'Use --agent <name> to configure explicitly (claude, cursor, codex, '
            'opencode, github-copilot, gemini-cli, or "all").',
            file=sys.stderr,
        )
        sys.exit(2)

    any_failed = False
    written_paths = set()
    for agent in agents:
        status, message = _configure_agent(agent, directory, bool(args.force), written_paths)
        print(message)
        if status == 'failed':
            any_failed = True

    sys.exit(1 if any_failed else 0)


def main():
    argv = _inject_scan_default(sys.argv)

    parser = argparse.ArgumentParser(
        prog='prodcycle',
        description='Multi-framework policy-as-code compliance scanner for infrastructure and application code.',
    )
    parser.add_argument(
        '-V', '--version',
        action='version',
        version=f'%(prog)s {__version__}',
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # scan
    p_scan = subparsers.add_parser('scan', help='Scan a repository for compliance violations')
    p_scan.add_argument('repo_path', nargs='?', default='.', help='Path to the repository to scan')
    _add_common_scan_args(p_scan)
    p_scan.set_defaults(func=_cmd_scan)

    # scans <scanId> — fetch status + findings of any scan by ID
    p_scans = subparsers.add_parser('scans', help='Get status + findings of a scan by ID')
    p_scans.add_argument('scan_id', help='The scanId returned by `scan --async` or `scan --chunked`')
    p_scans.add_argument('--format', default='json', help='Output format: json, sarif, table, prompt')
    p_scans.add_argument('--output', help='Write report to file')
    p_scans.add_argument('--api-url', help='Compliance API base URL (or PC_API_URL env)')
    p_scans.add_argument('--api-key', help='API key for compliance API (or PC_API_KEY env)')
    p_scans.set_defaults(func=_cmd_scans)

    # gate
    p_gate = subparsers.add_parser('gate', help='Evaluate a JSON payload of files from stdin')
    p_gate.add_argument('--framework', default='soc2', help='Comma-separated framework IDs to evaluate')
    p_gate.add_argument('--format', default='prompt', help='Output format: json, sarif, table, prompt')
    p_gate.add_argument('--output', help='Write report to file')
    p_gate.add_argument('--api-url', help='Compliance API base URL (or PC_API_URL env)')
    p_gate.add_argument('--api-key', help='API key for compliance API (or PC_API_KEY env)')
    p_gate.set_defaults(func=_cmd_gate)

    # hook
    p_hook = subparsers.add_parser('hook', help='Run as coding-agent post-edit hook (reads stdin or --file)')
    p_hook.add_argument('--framework', default='soc2', help='Comma-separated framework IDs to evaluate')
    p_hook.add_argument('--format', default='prompt', help='Output format: json, sarif, table, prompt')
    p_hook.add_argument('--file', help='Scan this file from disk (alternative to reading content from stdin)')
    p_hook.add_argument('--fail-on', default='critical,high', help='Severities that cause non-zero exit')
    p_hook.add_argument('--output', help='Write report to file')
    p_hook.add_argument('--api-url', help='Compliance API base URL (or PC_API_URL env)')
    p_hook.add_argument('--api-key', help='API key for compliance API (or PC_API_KEY env)')
    p_hook.set_defaults(func=_cmd_hook)

    # init
    p_init = subparsers.add_parser('init', help='Configure compliance hooks for coding agents')
    p_init.add_argument(
        '--agent',
        help=(
            'Comma-separated agents to configure (claude, cursor, codex, opencode, '
            'github-copilot, gemini-cli). Use "all" to configure every agent. '
            'Default: auto-detect.'
        ),
    )
    p_init.add_argument('--force', action='store_true', help='Overwrite existing compliance hook entries')
    p_init.add_argument('--dir', default='.', help='Project directory to configure')
    p_init.set_defaults(func=_cmd_init)

    args = parser.parse_args(argv[1:])

    try:
        args.func(args)
    except SystemExit:
        raise
    except Exception as e:
        print(f"\u2717 Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
