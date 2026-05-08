import xml.etree.ElementTree as ET
from typing import List
from razorscan.core.requester import RazorRequester

class SitemapParser:
    def __init__(self, requester: RazorRequester):
        self.requester = requester

    async def parse(self, base_url: str) -> List[str]:
        sitemap_url = f"{base_url.rstrip('/')}/sitemap.xml"
        response = await self.requester.fetch(sitemap_url)
        
        urls = []
        if response and response.status_code == 200:
            try:
                # Menghilangkan namespace jika ada untuk kemudahan parsing
                root = ET.fromstring(response.text)
                for loc in root.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc"):
                    urls.append(loc.text)
            except Exception:
                pass
        return urls

