def format_sarif(report):
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "ProdCycle Compliance Scanner"}}, "results": []}]
    }
