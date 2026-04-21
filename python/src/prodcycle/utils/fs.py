import os
import re

MAX_FILE_SIZE = 256 * 1024  # 256 KB
MAX_TOTAL_FILES = 10_000

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
