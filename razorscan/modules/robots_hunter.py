import re
from typing import List, Set
from razorscan.core.requester import RazorRequester

class RobotsHunter:
    def __init__(self, requester: RazorRequester):
        self.requester = requester

    async def find_hidden_paths(self, base_url: str) -> Set[str]:
        paths = set()
        robots_url = f"{base_url.rstrip('/')}/robots.txt"
        response = await self.requester.fetch(robots_url)
        
        if response and response.status_code == 200:
            # Cari baris Disallow: /path
            matches = re.findall(r'(?i)Disallow:\s*(/\S+)', response.text)
            for m in matches:
                if "*" not in m: # Skip wildcard
                    paths.add(m.strip())
        
        # Cek juga security.txt
        security_url = f"{base_url.rstrip('/')}/.well-known/security.txt"
        sec_resp = await self.requester.fetch(security_url)
        if sec_resp and sec_resp.status_code == 200:
            # Cari Contact atau Acknowledgments
            if "Contact" in sec_resp.text:
                paths.add("/.well-known/security.txt")
                
        return paths

