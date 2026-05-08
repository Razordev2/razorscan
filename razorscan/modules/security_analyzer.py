from typing import Dict, List, Any
import httpx
from bs4 import BeautifulSoup

class SecurityAnalyzer:
    def __init__(self, response: httpx.Response):
        self.headers = response.headers
        self.content = response.text
        self.url = response.url

    def analyze(self) -> Dict[str, Any]:
        results = {
            "missing_headers": [],
            "weak_headers": [],
            "cookies": [],
            "info": {}
        }

        # Check Security Headers
        security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]

        for header in security_headers:
            if header not in self.headers:
                results["missing_headers"].append(header)

        # CORS Analysis
        cors = self.headers.get("Access-Control-Allow-Origin")
        if cors == "*":
            results["weak_headers"].append({"header": "CORS", "value": "*", "risk": "High"})

        # Cookie Analysis
        for name, value in self.headers.items():
            if name.lower() == "set-cookie":
                cookie_info = {"raw": value, "issues": []}
                if "Secure" not in value: cookie_info["issues"].append("Missing Secure flag")
                if "HttpOnly" not in value: cookie_info["issues"].append("Missing HttpOnly flag")
                if "SameSite" not in value: cookie_info["issues"].append("Missing SameSite attribute")
                results["cookies"].append(cookie_info)

        return results

