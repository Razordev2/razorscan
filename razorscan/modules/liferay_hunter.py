from typing import List, Dict
from razorscan.core.requester import RazorRequester

class LiferayHunter:
    # Endpoint Liferay yang sering terekspos dan berisi data sensitif
    LIFERAY_PATHS = [
        "api/jsonws",                    # API Console (Sering bisa IDOR/RCE)
        "c/portal/login",                # Portal Login
        "group/control_panel/manage",    # Control Panel
        "api/jsonws/user/get-user-by-id",# User lookup
        "api/jsonws/company/get-company-by-id",
        "o/api",                         # REST Documentation
        "o/oauth2/authorize",            # OAuth2
        "group/guest/~/control_panel/manage", # Hidden Admin
        "c/portal/layout?p_l_id=1",      # Layout leak
        "combo/?browserId=chrome&minifierType=js&languageId=en_US&b=7410&t=1625612345678", # Minifier (Leak build)
    ]

    def __init__(self, requester: RazorRequester):
        self.requester = requester

    async def hunt(self, base_url: str) -> List[Dict[str, str]]:
        findings = []
        for path in self.LIFERAY_PATHS:
            target = f"{base_url.rstrip('/')}/{path}"
            response = await self.requester.fetch(target)
            if response and response.status_code in [200, 403, 401]:
                status_desc = "Open" if response.status_code == 200 else "Protected (403/401)"
                findings.append({
                    "path": path,
                    "url": target,
                    "type": f"Liferay {status_desc}"
                })
        return findings

