import re
from typing import List, Dict, Set
from razorscan.core.requester import RazorRequester

class JSExtractor:
    # Regex untuk mencari endpoint, URL, dan API Key ringan
    URL_REGEX = r'\"(https?://[\w\.-]+[^\"]*)\"|\' (https?://[\w\.-]+[^\']*)\''
    PATH_REGEX = r'\"(\/[\w\.\-\/]+)\"|\'(\/[\w\.\-\/]+)\''
    SECRET_REGEX = r'(?i)(api[_-]key|secret|token|auth|bearer|password|aws_access_key)[\s:=]+[\"\']([\w\.-]+)[\"\']'

    def __init__(self, requester: RazorRequester):
        self.requester = requester

    async def extract_from_url(self, js_url: str) -> Dict[str, List[str]]:
        response = await self.requester.fetch(js_url)
        if not response:
            return {}

        content = response.text
        results = {
            "endpoints": list(set(re.findall(self.PATH_REGEX, content))),
            "urls": list(set(re.findall(self.URL_REGEX, content))),
            "secrets": list(set(re.findall(self.SECRET_REGEX, content)))
        }
        
        # Flatten results (karena regex group)
        results["endpoints"] = [e[0] or e[1] for e in results["endpoints"] if (e[0] or e[1])]
        results["urls"] = [u[0] or u[1] for u in results["urls"] if (u[0] or u[1])]
        
        return results

