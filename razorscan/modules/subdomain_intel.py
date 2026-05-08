from typing import List, Set
from razorscan.core.requester import RazorRequester

class SubdomainIntel:
    def __init__(self, requester: RazorRequester):
        self.requester = requester

    async def discover(self, domain: str) -> Set[str]:
        """
        Cari subdomain menggunakan crt.sh (Certificate Transparency Logs).
        """
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        data = await self.requester.get_json(url)
        
        subdomains = set()
        if data:
            for entry in data:
                name = entry.get("name_value", "")
                # Handle multi-domain entries
                for sub in name.split("\n"):
                    if domain in sub and "*" not in sub:
                        subdomains.add(sub.strip().lower())
        return subdomains

