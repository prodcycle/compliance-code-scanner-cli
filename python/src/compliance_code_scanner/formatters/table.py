def format_table(report):
    if not report:
        return 'No report data'
    summary = report.get("summary", {})
    return f"Scan Results: {summary.get('passed', 0)} passed, {summary.get('failed', 0)} failed."
