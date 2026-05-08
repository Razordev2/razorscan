import httpx
from typing import List, Set

class SubdomainHunter:
    def __init__(self):
        self.url = "https://crt.sh/?q={domain}&output=json"

    async def find_subdomains(self, domain: str) -> Set[str]:
        subdomains = set()
        # Alternative Source: HackerTarget
        alt_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(alt_url)
                if resp.status_code == 200:
                    lines = resp.text.split("\n")
                    for line in lines:
                        if "," in line:
                            subdomains.add(line.split(",")[0])
        except Exception:
            pass
        return subdomains

