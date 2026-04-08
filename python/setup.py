from setuptools import setup, Extension
from Cython.Build import cythonize
import os
import glob

# Collect all Python files in src/compliance_code_scanner/
extensions = []
for root, _, files in os.walk('src/compliance_code_scanner'):
    for file in files:
        if file.endswith('.py') and file != '__init__.py':
            filepath = os.path.join(root, file)
            module_name = filepath.replace('src/', '').replace('/', '.').replace('.py', '')
            extensions.append(Extension(module_name, [filepath]))

# Keep __init__.py purely as python file for package resolution
setup(
    ext_modules=cythonize(extensions, compiler_directives={'language_level': "3"}),
    options={'bdist_wheel': {'universal': True}}
)
