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
exports.collectFiles = collectFiles;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const minimatch_1 = require("minimatch");
const MAX_FILE_SIZE = 256 * 1024; // 256 KB
const MAX_TOTAL_FILES = 10_000;
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
function loadGitignore(repoPath) {
    try {
        const gitignorePath = path.join(repoPath, '.gitignore');
        if (!fs.existsSync(gitignorePath))
            return [];
        const content = fs.readFileSync(gitignorePath, 'utf-8');
        return content
            .split('\n')
            .map((line) => line.trim())
            .filter((line) => line && !line.startsWith('#') && !line.startsWith('!'))
            .map((line) => (line.endsWith('/') ? line.slice(0, -1) : line));
    }
    catch {
        return [];
    }
}
function matchesAny(filePath, patterns) {
    return patterns.some((p) => (0, minimatch_1.minimatch)(filePath, p));
}
/**
 * Decide whether a directory or file entry should be excluded from collection.
 * Mirrors server `shouldIgnore` so scanner results stay consistent between
 * client-collected (CLI) and server-collected paths.
 */
function shouldIgnore(name, relPath, ignores, userExcludes) {
    if (SKIP_DIRS.has(name) ||
        SKIP_DIR_SUFFIXES.some((s) => name.endsWith(s)) ||
        (name.startsWith('.') &&
            !name.startsWith('.env') &&
            !name.startsWith('.github') &&
            !name.startsWith('.gitlab'))) {
        return true;
    }
    if (userExcludes && userExcludes.length > 0) {
        for (const pattern of userExcludes) {
            if (name === pattern ||
                name + '/' === pattern ||
                relPath === pattern ||
                relPath + '/' === pattern) {
                return true;
            }
        }
        if (matchesAny(relPath, userExcludes))
            return true;
    }
    // .env* files are always scanned, even if listed in .gitignore (common case)
    if (name.startsWith('.env') || name.endsWith('.env'))
        return false;
    for (const pattern of ignores) {
        if (name === pattern ||
            name + '/' === pattern ||
            relPath === pattern ||
            relPath + '/' === pattern) {
            return true;
        }
    }
    if (matchesAny(relPath, ignores))
        return true;
    return false;
}
function isBinary(buffer) {
    for (let i = 0; i < Math.min(buffer.length, 1024); i++) {
        if (buffer[i] === 0)
            return true;
    }
    return false;
}
function shouldSkipFileByName(name) {
    if (SKIP_FILE_NAMES.has(name))
        return true;
    return SKIP_FILE_EXTENSIONS.some((ext) => name.endsWith(ext));
}
async function collectFiles(baseDir, includePatterns, excludePatterns) {
    const repoRoot = path.resolve(baseDir);
    const ignores = loadGitignore(repoRoot);
    const files = {};
    const state = { count: 0, limitReached: false };
    walk(repoRoot, repoRoot, ignores, includePatterns, excludePatterns, files, state);
    return files;
}
function walk(dir, repoRoot, ignores, includePatterns, userExcludes, files, state) {
    if (state.limitReached)
        return;
    let entries;
    try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
    }
    catch {
        return;
    }
    for (const entry of entries) {
        if (state.limitReached)
            return;
        const name = entry.name;
        const fullPath = path.join(dir, name);
        const relPath = path.relative(repoRoot, fullPath);
        if (entry.isDirectory()) {
            if (shouldIgnore(name, relPath, ignores, userExcludes))
                continue;
            walk(fullPath, repoRoot, ignores, includePatterns, userExcludes, files, state);
            continue;
        }
        if (!entry.isFile())
            continue;
        if (shouldIgnore(name, relPath, ignores, userExcludes))
            continue;
        if (shouldSkipFileByName(name))
            continue;
        if (includePatterns && includePatterns.length > 0 && !matchesAny(relPath, includePatterns)) {
            continue;
        }
        if (state.count >= MAX_TOTAL_FILES) {
            console.warn(`Reached max file limit (${MAX_TOTAL_FILES}). Some files were skipped.`);
            state.limitReached = true;
            return;
        }
        let stats;
        try {
            stats = fs.statSync(fullPath);
        }
        catch {
            continue;
        }
        if (stats.size > MAX_FILE_SIZE)
            continue;
        let buffer;
        try {
            buffer = fs.readFileSync(fullPath);
        }
        catch {
            continue;
        }
        if (isBinary(buffer))
            continue;
        files[relPath] = buffer.toString('utf8');
        state.count++;
    }
}
