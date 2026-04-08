from .api_client import ComplianceApiClient
from .utils.fs import collect_files
from .formatters.table import format_table
from .formatters.prompt import format_prompt
from .formatters.sarif import format_sarif

__all__ = [
    'ComplianceApiClient',
    'scan',
    'gate',
    'run_hook',
    'run_hook_api',
    'format_table',
    'format_prompt',
    'format_sarif',
]

def scan(repo_path: str, frameworks: list[str] = None, options: dict = None) -> dict:
    if frameworks is None:
        frameworks = ['soc2']
    if options is None:
        options = {}
        
    include = options.get('include')
    exclude = options.get('exclude')
    
    files = collect_files(repo_path, include_patterns=include, exclude_patterns=exclude)
    
    if not files:
        return {
            'passed': True,
            'exitCode': 0,
            'findings': [],
            'report': None,
            'summary': {}
        }
        
    client = ComplianceApiClient(options.get('apiUrl'), options.get('apiKey'))
    response = client.validate(files, frameworks, options)
    
    passed = response.get('passed', False)
    
    return {
        'passed': passed,
        'exitCode': 0 if passed else 1,
        'findings': response.get('findings', []),
        'report': response.get('report'),
        'summary': response.get('summary', {})
    }

def gate(files: dict, frameworks: list[str] = None, severity_threshold: str = "medium", fail_on: list[str] = None, config: dict = None, api_url: str = None, api_key: str = None) -> dict:
    if frameworks is None:
        frameworks = ['soc2']
    if fail_on is None:
        fail_on = ["critical", "high"]
        
    client = ComplianceApiClient(api_url, api_key)
    
    # We call the hook API since we don't have the full validate structure locally
    # Gate typically is for real-time analysis
    response = client.hook(files, frameworks)
    
    passed = response.get('passed', False)
    
    return {
        'passed': passed,
        'exitCode': 0 if passed else 1,
        'findings': response.get('findings', []),
        'prompt': response.get('prompt', ''),
        'summary': response.get('summary', {})
    }

def run_hook(frameworks: list[str] = None, file_path: str = None) -> int:
    if frameworks is None:
        frameworks = ['soc2']
    return 0

def run_hook_api(api_url: str = None, api_key: str = None, frameworks: list[str] = None) -> int:
    if frameworks is None:
        frameworks = ['soc2']
    return 0
