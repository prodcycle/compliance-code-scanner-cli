import os
import re

MAX_FILE_SIZE = 256 * 1024  # 256 KB

# Total file ceiling per scan. Hit on the OSS-CLI benchmark scanning
# hapifhir/hapi-fhir (~13k files) — the CLI silently dropped ~3k files
# past the cap. Raised from the original 10k to 50k. The API's chunked-
# session endpoint already supports up to 2,000 files per chunk, so a
# 50k-file repo is fed in 25+ chunks; the cap is here purely so a
# pathological symlink loop or .git-tracked-as-source repo doesn't
# exhaust the client's memory before the SCANNABLE_EXTENSIONS filter
# has a chance to drop most of the entries.
#
# Combined with the SCANNABLE_EXTENSIONS allowlist below, this should
# cover effectively every real-world OSS repo. If you hit this cap on
# a non-pathological repo, file an issue — we'd rather raise it than
# have the CLI silently truncate.
MAX_TOTAL_FILES = 50_000

# Extensions and exact filenames the server-side `isScannable` filter
# accepts. Pre-filtering client-side avoids:
#   - bloating the wire payload with images / fonts / docs / archives
#     that the API just drops on receipt
#   - hitting MAX_TOTAL_FILES on repos like hapi-fhir or the Linux
#     kernel where most files are not scannable
#
# Keep in lock-step with api/src/domain/services/compliance-scan.service.ts:
#   - APPLICATION_CODE_EXTENSIONS (the source-code allowlist)
#   - INFRASTRUCTURE_EXTENSIONS (.tf, .yaml, .yml, .json, .sql)
#   - INFRASTRUCTURE_FILENAMES (dockerfile, .env)
#
# AND with node/src/utils/fs.ts SCANNABLE_EXTENSIONS (sibling implementation).
# Source-of-truth is the server filter; this is just an optimization so we
# don't pay the wire cost for files the server will reject anyway.
SCANNABLE_EXTENSIONS = frozenset({
    # Application code (mirrors APPLICATION_CODE_EXTENSIONS in the API)
    '.ts', '.tsx', '.js', '.jsx',
    '.py', '.go', '.java', '.rb',
    '.php', '.rs', '.cs', '.kt', '.scala',
    '.c', '.cpp', '.h', '.hpp',
    # Infrastructure-as-code (mirrors INFRASTRUCTURE_EXTENSIONS in the API)
    '.tf', '.yaml', '.yml', '.json', '.sql',
})

SCANNABLE_FILENAMES = frozenset({
    'dockerfile',
    'containerfile',
    '.env',
})

# Directories skipped unconditionally. Kept in parity with
# packages/compliance-code-scanner/src/ignore-utils.ts (SKIP_DIRS).
SKIP_DIRS = frozenset({
    'node_modules',
    'vendor',
    '__pycache__',
    '.terraform',
    '.git',
    'dist',
    '.venv',
    'venv',
    'build',
    'out',
    '.next',
    '.nuxt',
    '.output',
    '.cache',
    '.parcel-cache',
    'coverage',
    '.nyc_output',
    '.turbo',
    'target',
    '.gradle',
    '.mvn',
    '.idea',
    '.vscode',
    '.eggs',
    '.tox',
    '.mypy_cache',
    '.ruff_cache',
    '.pytest_cache',
    'bower_components',
    '.svn',
    '.hg',
    '__snapshots__',
})

SKIP_DIR_SUFFIXES = ('.egg-info',)

SKIP_FILE_EXTENSIONS = ('.lock', '.min.js', '.min.css', '.map', '.bundle.js', '.tfstate', '.tfstate.backup')
SKIP_FILE_NAMES = frozenset({'package-lock.json'})


def _glob_to_regex(pattern):
    """Convert a glob pattern (minimatch-style) to a regex.

    Supports `**` (any path depth, including zero segments), `*` (any chars
    except `/`), and `?` (single char). Mirrors the subset of minimatch
    behavior the server relies on.
    """
    i = 0
    out = []
    while i < len(pattern):
        c = pattern[i]
        if c == '*':
            if i + 1 < len(pattern) and pattern[i + 1] == '*':
                # `**/` → match any number of path segments (including zero)
                if i + 2 < len(pattern) and pattern[i + 2] == '/':
                    out.append('(?:.*/)?')
                    i += 3
                    continue
                out.append('.*')
                i += 2
                continue
            out.append('[^/]*')
            i += 1
            continue
        if c == '?':
            out.append('[^/]')
            i += 1
            continue
        out.append(re.escape(c))
        i += 1
    return re.compile('^' + ''.join(out) + '$')


def _matches_any(file_path, patterns):
    # Normalize to forward slashes so patterns behave the same on Windows
    normalized = file_path.replace(os.sep, '/')
    for p in patterns:
        if _glob_to_regex(p).match(normalized):
            return True
    return False


def load_gitignore(repo_path):
    """Load .gitignore patterns from the repo root.

    Negation patterns (`!foo`) are dropped — they cannot be translated to the
    simple glob matcher used here without losing directory-descent semantics
    (mirrors server-side fix in ignore-utils.ts).
    """
    gitignore_path = os.path.join(repo_path, '.gitignore')
    if not os.path.exists(gitignore_path):
        return []
    try:
        with open(gitignore_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception:
        return []

    patterns = []
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('!'):
            continue
        if line.endswith('/'):
            line = line[:-1]
        patterns.append(line)
    return patterns


def should_ignore(name, rel_path, ignores, user_excludes=None):
    """Mirror of server `shouldIgnore` so scanner results stay consistent
    between client-collected (CLI) and server-collected paths."""
    if name in SKIP_DIRS:
        return True
    if any(name.endswith(s) for s in SKIP_DIR_SUFFIXES):
        return True
    if (
        name.startswith('.')
        and not name.startswith('.env')
        and not name.startswith('.github')
        and not name.startswith('.gitlab')
    ):
        return True

    if user_excludes:
        for pattern in user_excludes:
            if (
                name == pattern
                or name + '/' == pattern
                or rel_path == pattern
                or rel_path + '/' == pattern
            ):
                return True
        if _matches_any(rel_path, user_excludes):
            return True

    # .env* files are always scanned, even if listed in .gitignore
    if name.startswith('.env') or name.endswith('.env'):
        return False

    for pattern in ignores:
        if (
            name == pattern
            or name + '/' == pattern
            or rel_path == pattern
            or rel_path + '/' == pattern
        ):
            return True

    if _matches_any(rel_path, ignores):
        return True

    return False


def is_binary(file_path):
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            return b'\0' in chunk
    except Exception:
        return True


def _should_skip_file_by_name(name):
    if name in SKIP_FILE_NAMES:
        return True
    return any(name.endswith(ext) for ext in SKIP_FILE_EXTENSIONS)


def _is_scannable_filename(name):
    """Mirror of the server's `isScannable` filter, applied client-side so we
    don't ship files the API will just drop. Also keeps repos like hapi-fhir
    (~13k files, mostly Java + some CSS/HTML/templates) from tripping
    MAX_TOTAL_FILES on non-scannable noise.
    """
    lower = name.lower()
    if lower in SCANNABLE_FILENAMES:
        return True
    # Dockerfile variants (dockerfile.prod, dockerfile.dev, …)
    if lower.startswith('dockerfile.'):
        return True
    # .env variants (.env.staging, .env.production, …)
    if lower.startswith('.env.'):
        return True
    dot = lower.rfind('.')
    if dot == -1:
        return False
    return lower[dot:] in SCANNABLE_EXTENSIONS


def collect_files(base_dir, include_patterns=None, exclude_patterns=None):
    repo_root = os.path.abspath(base_dir)
    ignores = load_gitignore(repo_root)
    files = {}
    state = {'count': 0, 'limit_reached': False}

    _walk(repo_root, repo_root, ignores, include_patterns, exclude_patterns, files, state)
    return files


def _walk(dir_path, repo_root, ignores, include_patterns, user_excludes, files, state):
    if state['limit_reached']:
        return

    try:
        entries = list(os.scandir(dir_path))
    except OSError:
        return

    for entry in entries:
        if state['limit_reached']:
            return

        name = entry.name
        full_path = entry.path
        rel_path = os.path.relpath(full_path, repo_root)

        try:
            is_dir = entry.is_dir(follow_symlinks=False)
        except OSError:
            continue

        if is_dir:
            if should_ignore(name, rel_path, ignores, user_excludes):
                continue
            _walk(full_path, repo_root, ignores, include_patterns, user_excludes, files, state)
            continue

        try:
            is_file = entry.is_file(follow_symlinks=False)
        except OSError:
            continue
        if not is_file:
            continue

        if should_ignore(name, rel_path, ignores, user_excludes):
            continue
        if _should_skip_file_by_name(name):
            continue

        # Skip files the server-side `isScannable` filter will drop anyway.
        # When `--include` patterns are given we honor those instead —
        # explicit user intent overrides the server-shape allowlist.
        if not include_patterns and not _is_scannable_filename(name):
            continue

        if include_patterns and not _matches_any(rel_path, include_patterns):
            continue

        if state['count'] >= MAX_TOTAL_FILES:
            print(f"Warning: Reached max file limit ({MAX_TOTAL_FILES}). Some files were skipped.")
            state['limit_reached'] = True
            return

        try:
            stats = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if stats.st_size > MAX_FILE_SIZE:
            continue

        if is_binary(full_path):
            continue

        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except (OSError, UnicodeDecodeError):
            continue

        files[rel_path] = content
        state['count'] += 1
