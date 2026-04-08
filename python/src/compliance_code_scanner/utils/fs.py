import os
import glob

MAX_FILE_SIZE = 256 * 1024  # 256 KB
MAX_TOTAL_FILES = 500

def is_binary(file_path):
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            return b'\0' in chunk
    except Exception:
        return True

def collect_files(base_dir, include_patterns=None, exclude_patterns=None):
    if not include_patterns:
        include_patterns = ['**/*']
        
    ignore_list = [
        'node_modules', '.git', '.terraform', 'dist', 'build', '__pycache__', '.venv', 'venv'
    ]
    if exclude_patterns:
        ignore_list.extend(exclude_patterns)

    files = {}
    count = 0

    base_dir = os.path.abspath(base_dir)

    for pattern in include_patterns:
        # Use recursive globbing
        glob_pattern = os.path.join(base_dir, pattern)
        for filepath in glob.iglob(glob_pattern, recursive=True):
            if not os.path.isfile(filepath):
                continue
                
            # Check exclusions manually since standard python glob doesn't have an ignore kwarg
            rel_path = os.path.relpath(filepath, base_dir)
            should_ignore = False
            for ign in ignore_list:
                if ign in rel_path.split(os.sep) or rel_path.startswith(ign):
                    should_ignore = True
                    break
            
            if should_ignore:
                continue

            if count >= MAX_TOTAL_FILES:
                print(f"Warning: Reached max file limit ({MAX_TOTAL_FILES}). Some files were skipped.")
                return files

            try:
                stats = os.stat(filepath)
                if stats.st_size > MAX_FILE_SIZE:
                    continue

                if is_binary(filepath):
                    continue

                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                files[rel_path] = content
                count += 1
            except Exception:
                # Skip unreadable files
                pass

    return files
