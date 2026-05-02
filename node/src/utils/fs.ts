import * as fs from 'fs';
import * as path from 'path';
import { minimatch } from 'minimatch';

const MAX_FILE_SIZE = 256 * 1024; // 256 KB

/**
 * Total file ceiling per scan. Hit on the OSS-CLI benchmark scanning
 * `hapifhir/hapi-fhir` (~13k files) — the CLI silently dropped ~3k files
 * past the cap. Raised from the original 10k to 50k. The API's chunked-
 * session endpoint already supports up to 2,000 files per chunk, so a
 * 50k-file repo is fed in 25+ chunks; the cap is here purely so a
 * pathological symlink loop or `.git`-tracked-as-source repo doesn't
 * exhaust the client's memory before the SCANNABLE_EXTENSIONS filter
 * has a chance to drop most of the entries.
 *
 * Combined with the SCANNABLE_EXTENSIONS allowlist below, this should
 * cover effectively every real-world OSS repo. If you hit this cap on
 * a non-pathological repo, file an issue — we'd rather raise it than
 * have the CLI silently truncate.
 */
const MAX_TOTAL_FILES = 50_000;

/**
 * Extensions and exact filenames the server-side `isScannable` filter
 * accepts. Pre-filtering client-side avoids:
 *   - bloating the wire payload with images / fonts / docs / archives
 *     that the API just drops on receipt
 *   - hitting MAX_TOTAL_FILES on repos like hapi-fhir or the Linux
 *     kernel where most files are not scannable
 *
 * Keep in lock-step with `api/src/domain/services/compliance-scan.service.ts`:
 *   - APPLICATION_CODE_EXTENSIONS (the source-code allowlist)
 *   - INFRASTRUCTURE_EXTENSIONS (.tf, .yaml, .yml, .json, .sql)
 *   - INFRASTRUCTURE_FILENAMES (dockerfile, .env)
 *
 * Files outside this set are skipped during walk. Source-of-truth is
 * the server filter; this is just an optimization so we don't pay the
 * wire cost for files the server will reject anyway.
 */
const SCANNABLE_EXTENSIONS = new Set([
  // Application code (must mirror APPLICATION_CODE_EXTENSIONS in the API)
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.py',
  '.go',
  '.java',
  '.rb',
  '.php',
  '.rs',
  '.cs',
  '.kt',
  '.scala',
  '.c',
  '.cpp',
  '.h',
  '.hpp',
  // Infrastructure-as-code (must mirror INFRASTRUCTURE_EXTENSIONS in the API)
  '.tf',
  '.yaml',
  '.yml',
  '.json',
  '.sql',
]);

const SCANNABLE_FILENAMES = new Set([
  'dockerfile',
  'containerfile',
  '.env',
]);

/**
 * Directories skipped unconditionally. Kept in parity with
 * `packages/compliance-code-scanner/src/ignore-utils.ts`.
 */
const SKIP_DIRS = new Set([
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
]);

const SKIP_DIR_SUFFIXES = ['.egg-info'];

const SKIP_FILE_EXTENSIONS = ['.lock', '.min.js', '.min.css', '.map', '.bundle.js', '.tfstate', '.tfstate.backup'];
const SKIP_FILE_NAMES = new Set(['package-lock.json']);

/**
 * Load .gitignore patterns from the repo root.
 *
 * Negation patterns (`!foo`) are dropped — minimatch does not interpret them
 * as gitignore would, and passing them through causes directory-wide blindness
 * (see server-side fix in ignore-utils.ts).
 */
function loadGitignore(repoPath: string): string[] {
  try {
    const gitignorePath = path.join(repoPath, '.gitignore');
    if (!fs.existsSync(gitignorePath)) return [];
    const content = fs.readFileSync(gitignorePath, 'utf-8');
    return content
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#') && !line.startsWith('!'))
      .map((line) => (line.endsWith('/') ? line.slice(0, -1) : line));
  } catch {
    return [];
  }
}

function matchesAny(filePath: string, patterns: string[]): boolean {
  return patterns.some((p) => minimatch(filePath, p));
}

/**
 * Decide whether a directory or file entry should be excluded from collection.
 * Mirrors server `shouldIgnore` so scanner results stay consistent between
 * client-collected (CLI) and server-collected paths.
 */
function shouldIgnore(
  name: string,
  relPath: string,
  ignores: string[],
  userExcludes?: string[],
): boolean {
  if (
    SKIP_DIRS.has(name) ||
    SKIP_DIR_SUFFIXES.some((s) => name.endsWith(s)) ||
    (name.startsWith('.') &&
      !name.startsWith('.env') &&
      !name.startsWith('.github') &&
      !name.startsWith('.gitlab'))
  ) {
    return true;
  }

  if (userExcludes && userExcludes.length > 0) {
    for (const pattern of userExcludes) {
      if (
        name === pattern ||
        name + '/' === pattern ||
        relPath === pattern ||
        relPath + '/' === pattern
      ) {
        return true;
      }
    }
    if (matchesAny(relPath, userExcludes)) return true;
  }

  // .env* files are always scanned, even if listed in .gitignore (common case)
  if (name.startsWith('.env') || name.endsWith('.env')) return false;

  for (const pattern of ignores) {
    if (
      name === pattern ||
      name + '/' === pattern ||
      relPath === pattern ||
      relPath + '/' === pattern
    ) {
      return true;
    }
  }

  if (matchesAny(relPath, ignores)) return true;

  return false;
}

function isBinary(buffer: Buffer): boolean {
  for (let i = 0; i < Math.min(buffer.length, 1024); i++) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

function shouldSkipFileByName(name: string): boolean {
  if (SKIP_FILE_NAMES.has(name)) return true;
  return SKIP_FILE_EXTENSIONS.some((ext) => name.endsWith(ext));
}

/**
 * Mirror of the server's `isScannable` filter, applied client-side so we
 * don't ship files the API will just drop. Also keeps repos like
 * hapi-fhir (~13k files, mostly Java + some CSS/HTML/templates) from
 * tripping MAX_TOTAL_FILES on non-scannable noise.
 */
function isScannableFilename(name: string): boolean {
  const lower = name.toLowerCase();
  if (SCANNABLE_FILENAMES.has(lower)) return true;
  // Dockerfile variants (dockerfile.prod, dockerfile.dev, …)
  if (lower.startsWith('dockerfile.')) return true;
  // .env variants (.env.staging, .env.production, …)
  if (lower.startsWith('.env.')) return true;
  const dot = lower.lastIndexOf('.');
  if (dot === -1) return false;
  return SCANNABLE_EXTENSIONS.has(lower.slice(dot));
}

export async function collectFiles(
  baseDir: string,
  includePatterns?: string[],
  excludePatterns?: string[],
): Promise<Record<string, string>> {
  const repoRoot = path.resolve(baseDir);
  const ignores = loadGitignore(repoRoot);
  const files: Record<string, string> = {};
  const state = { count: 0, limitReached: false };

  walk(repoRoot, repoRoot, ignores, includePatterns, excludePatterns, files, state);

  return files;
}

function walk(
  dir: string,
  repoRoot: string,
  ignores: string[],
  includePatterns: string[] | undefined,
  userExcludes: string[] | undefined,
  files: Record<string, string>,
  state: { count: number; limitReached: boolean },
): void {
  if (state.limitReached) return;

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (state.limitReached) return;

    const name = entry.name;
    const fullPath = path.join(dir, name);
    const relPath = path.relative(repoRoot, fullPath);

    if (entry.isDirectory()) {
      if (shouldIgnore(name, relPath, ignores, userExcludes)) continue;
      walk(fullPath, repoRoot, ignores, includePatterns, userExcludes, files, state);
      continue;
    }

    if (!entry.isFile()) continue;
    if (shouldIgnore(name, relPath, ignores, userExcludes)) continue;
    if (shouldSkipFileByName(name)) continue;

    // Skip files the server-side `isScannable` filter will drop anyway.
    // No point paying the wire cost. When `--include` patterns are given
    // we honor those instead — explicit user intent overrides the
    // server-shape allowlist.
    if (
      (!includePatterns || includePatterns.length === 0) &&
      !isScannableFilename(name)
    ) {
      continue;
    }

    if (includePatterns && includePatterns.length > 0 && !matchesAny(relPath, includePatterns)) {
      continue;
    }

    if (state.count >= MAX_TOTAL_FILES) {
      console.warn(`Reached max file limit (${MAX_TOTAL_FILES}). Some files were skipped.`);
      state.limitReached = true;
      return;
    }

    let stats: fs.Stats;
    try {
      stats = fs.statSync(fullPath);
    } catch {
      continue;
    }

    if (stats.size > MAX_FILE_SIZE) continue;

    let buffer: Buffer;
    try {
      buffer = fs.readFileSync(fullPath);
    } catch {
      continue;
    }

    if (isBinary(buffer)) continue;

    files[relPath] = buffer.toString('utf8');
    state.count++;
  }
}
