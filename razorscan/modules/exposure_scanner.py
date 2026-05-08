from typing import List, Dict, Any
from razorscan.core.requester import RazorRequester
from yarl import URL

class ExposureScanner:
    SENSITIVE_FILES = [
        # API Gold Mines
        "swagger-ui.html", "v1/swagger.json", "v2/swagger.json", "swagger.yaml",
        "api-docs", "v1/api-docs", "graphql", "graphiql",
        
        # Environment & Cloud
        ".env", ".git/config", "web.config", "phpinfo.php",
        ".aws/credentials", ".s3cfg",
        
        # Java/Spring Boot Actuators (High Impact)
        "actuator", "actuator/env", "actuator/heapdump", "actuator/mappings",
        "jolokia", "configprops",
        
        # Common Configs
        "robots.txt", "security.txt", "sitemap.xml",
        ".vscode/settings.json", "backup.zip", "config.php.bak"
    ]

    def __init__(self, requester: RazorRequester):
        self.requester = requester

    async def scan(self, base_url: str) -> List[Dict[str, Any]]:
        results = []
        parsed_base = URL(base_url)
        
        for path in self.SENSITIVE_FILES:
            target = str(parsed_base.joinpath(path))
            response = await self.requester.fetch(target, method="GET")
            
            if response and response.status_code == 200:
                # Basic check to avoid false positives (e.g. 404 pages returning 200)
                if len(response.text) > 0 and "html" not in response.headers.get("Content-Type", "").lower():
                    results.append({
                        "path": path,
                        "status": response.status_code,
                        "size": len(response.text),
                        "url": target
                    })
        return results

