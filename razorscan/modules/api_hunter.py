from typing import List, Dict
from razorscan.core.requester import RazorRequester

class APIHunter:
    # Path dokumentasi API yang sering terbuka
    DOC_PATHS = [
        "/swagger-ui.html",
        "/swagger-ui/",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger.json",
        "/api/docs",
        "/api/swagger.json",
        "/api/v1/docs",
        "/docs",
        "/openapi.json",
        "/api-docs"
    ]

    def __init__(self, requester: RazorRequester):
        self.requester = requester

    async def find_docs(self, url: str) -> List[Dict[str, str]]:
        findings = []
        base_url = url.rstrip("/")
        for path in self.DOC_PATHS:
            target = f"{base_url}{path}"
            resp = await self.requester.fetch(target)
            if resp and resp.status_code == 200:
                findings.append({
                    "url": target,
                    "type": "Exposed API Documentation (Swagger/OpenAPI)"
                })
        return findings

