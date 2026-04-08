import os
import json
import urllib.request
import urllib.error

class ComplianceApiClient:
    def __init__(self, api_url=None, api_key=None):
        self.api_url = api_url or os.environ.get('PC_API_URL', 'https://api.prodcycle.com')
        self.api_key = api_key or os.environ.get('PC_API_KEY', '')

        if not self.api_key and os.environ.get('PYTEST_CURRENT_TEST') is None:
            print("Warning: PC_API_KEY is not set. API calls will likely fail.")

    def validate(self, files, frameworks, options=None):
        options = options or {}
        
        # Merge basic options with config overrides
        opts_payload = {
            "severity_threshold": options.get("severityThreshold", "low"),
            "fail_on": options.get("failOn", ["critical", "high"])
        }
        if "config" in options:
            opts_payload.update(options["config"])
            
        data = {
            "files": files,
            "frameworks": frameworks,
            "options": opts_payload
        }
        return self._post('/v1/compliance/validate', data)

    def hook(self, files, frameworks):
        data = {
            "files": files,
            "frameworks": frameworks
        }
        return self._post('/v1/compliance/hook', data)

    def _post(self, endpoint, data):
        url = f"{self.api_url}{endpoint}"
        req = urllib.request.Request(url, method="POST")
        req.add_header("Authorization", f"Bearer {self.api_key}")
        req.add_header("Content-Type", "application/json")

        payload = json.dumps(data).encode('utf-8')
        
        try:
            with urllib.request.urlopen(req, data=payload) as response:
                response_data = response.read().decode('utf-8')
                return json.loads(response_data)
        except urllib.error.HTTPError as e:
            try:
                err_body = e.read().decode('utf-8')
                err_data = json.loads(err_body)
                msg = err_data.get("error", {}).get("message", str(e))
                raise Exception(msg)
            except Exception as parse_e:
                if str(parse_e) == str(e) or not err_body:
                    raise Exception(f"API request failed with status {e.code}")
                raise Exception(err_body)
        except urllib.error.URLError as e:
            raise Exception(f"Failed to connect to ProdCycle API: {e.reason}")
