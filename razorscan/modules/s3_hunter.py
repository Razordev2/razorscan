from typing import List, Dict
from razorscan.core.requester import RazorRequester

class S3Hunter:
    def __init__(self, requester: RazorRequester):
        self.requester = requester

    async def check_buckets(self, domain: str) -> List[Dict[str, str]]:
        findings = []
        base_name = domain.split(".")[0]
        # Daftar nama bucket yang potensial
        potential_buckets = [
            base_name,
            f"{base_name}-assets",
            f"{base_name}-public",
            f"{base_name}-data",
            f"{base_name}-staging",
            f"nasa-{base_name}",
            "globe-gov-assets",
            "globe-data"
        ]

        for bucket in potential_buckets:
            url = f"https://{bucket}.s3.amazonaws.com"
            resp = await self.requester.fetch(url)
            if resp and resp.status_code == 200:
                findings.append({
                    "bucket": bucket,
                    "url": url,
                    "status": "Publicly Accessible (OPEN!)"
                })
            elif resp and resp.status_code == 403:
                 # 403 berarti bucket ada tapi diproteksi (tetap info berharga)
                 pass
        return findings

