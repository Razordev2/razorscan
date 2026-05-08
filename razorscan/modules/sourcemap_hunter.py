from typing import List, Dict
from razorscan.core.requester import RazorRequester

class SourceMapHunter:
    def __init__(self, requester: RazorRequester):
        self.requester = requester

    async def find_maps(self, js_urls: List[str]) -> List[Dict[str, str]]:
        findings = []
        for js_url in js_urls:
            map_url = f"{js_url}.map"
            response = await self.requester.fetch(map_url)
            if response and response.status_code == 200:
                findings.append({
                    "url": map_url,
                    "type": "JavaScript Source Map Exposed"
                })
        return findings

