import sys
import json
import argparse
from compliance_code_scanner import scan, gate

def main():
    parser = argparse.ArgumentParser(
        prog='compliance-code-scanner',
        description='Multi-framework policy-as-code compliance scanner for infrastructure and application code.'
    )
    
    parser.add_argument('repo_path', nargs='?', default='.', help='Path to the repository to scan')
    parser.add_argument('--framework', default='soc2', help='Comma-separated framework IDs to evaluate')
    parser.add_argument('--format', default='table', help='Output format: json, sarif, table, prompt')
    parser.add_argument('--severity-threshold', default='low', help='Minimum severity to include in report')
    parser.add_argument('--fail-on', default='critical,high', help='Comma-separated severities that cause non-zero exit')
    parser.add_argument('--include', help='Comma-separated glob patterns to include')
    parser.add_argument('--exclude', help='Comma-separated glob patterns to exclude')
    parser.add_argument('--output', help='Write report to file')
    parser.add_argument('--api-url', help='Compliance API base URL (or PC_API_URL env)')
    parser.add_argument('--api-key', help='API key for compliance API (or PC_API_KEY env)')
    parser.add_argument('--hook', action='store_true', help='Run as coding agent post-edit hook (reads stdin)')
    parser.add_argument('--hook-file', help='File path for hook mode (alternative to stdin)')
    parser.add_argument('--hook-api', action='store_true', help='Run as API-based hook (calls hosted compliance API)')
    parser.add_argument('--init', action='store_true', help='Set up compliance hooks for coding agents')
    parser.add_argument('--agent', help='Comma-separated agents to configure')
    
    args = parser.parse_args()
    
    try:
        if args.hook or args.hook_api:
            print('Hook mode executed.')
            sys.exit(0)
            
        if args.init:
            print('Init mode executed.')
            sys.exit(0)
            
        frameworks = [s.strip() for s in args.framework.split(',')]
        fail_on = [s.strip() for s in args.fail_on.split(',')]
        include = [s.strip() for s in args.include.split(',')] if args.include else None
        exclude = [s.strip() for s in args.exclude.split(',')] if args.exclude else None
        
        print(f"Scanning {args.repo_path} for {', '.join(frameworks)}...")
        
        response = scan(
            repo_path=args.repo_path,
            frameworks=frameworks,
            options={
                'severityThreshold': args.severity_threshold,
                'failOn': fail_on,
                'include': include,
                'exclude': exclude,
                'apiUrl': args.api_url,
                'apiKey': args.api_key,
            }
        )
        
        if args.format == 'json':
            output = json.dumps(response, indent=2)
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(output)
            else:
                print(output)
        else:
            print(f"Passed: {response.get('passed')}")
            print(f"Findings: {len(response.get('findings', []))}")
            
        sys.exit(response.get('exitCode', 1))
        
    except Exception as e:
        print(f"✗ Error: {str(e)}", file=sys.stderr)
        sys.exit(2)

if __name__ == '__main__':
    main()
