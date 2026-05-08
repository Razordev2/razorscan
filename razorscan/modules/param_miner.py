from typing import List, Dict
from razorscan.core.requester import RazorRequester

class ParamMiner:
    # Parameter yang seringkali bisa dimanipulasi untuk bypass
    HIDDEN_PARAMS = [
        "admin=true",
        "debug=1",
        "test=1",
        "role=admin",
        "privilege=high",
        "is_admin=1",
        "config=true",
        "internal=true",
        "show_all=true"
    ]

    def __init__(self, requester: RazorRequester):
        self.requester = requester

    async def mine(self, url: str) -> List[Dict[str, str]]:
        findings = []
        base_url = url.split("?")[0]
        for p in self.HIDDEN_PARAMS:
            target = f"{base_url}?{p}"
            response = await self.requester.fetch(target)
            if response and response.status_code == 200:
                # Jika response berbeda dengan original, ada indikasi parameter sakti
                findings.append({
                    "parameter": p,
                    "url": target,
                    "status": "Potential Trigger Found"
                })
        return findings

