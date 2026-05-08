import json
from typing import List, Set
from razorscan.core.requester import RazorRequester

class WaybackIntel:
    def __init__(self, requester: RazorRequester):
        self.requester = requester

    async def get_urls(self, domain: str, limit: int = 50) -> Set[str]:
        """
        Ambil URL historis dari Wayback Machine.
        """
        # API CDX Wayback
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&limit={limit}"
        
        response = await self.requester.fetch(url)
        if not response or response.status_code != 200:
            return set()
        
        try:
            data = response.json()
            if not data or len(data) < 2:
                return set()
            
            # Baris pertama adalah header [urlkey, timestamp, original, ...]
            # Kita ambil index 2 (original URL)
            return {entry[2] for entry in data[1:]}
        except Exception:
            return set()

