from typing import List, Dict
from razorscan.core.requester import RazorRequester

class MoodleHunter:
    # Path sensitif Moodle
    SENSITIVE_PATHS = [
        "/config.php",
        "/admin/cli/",
        "/lib/upgrade.txt",
        "/lib/db/install.xml",
        "/user/pix.php",
        "/local/mobile/check.php",
        "/admin/tool/behat/tests/behat/behat.yml",
        "/theme/upgrade.txt",
        "/report/log/upgrade.txt",
        "/mod/forum/upgrade.txt"
    ]

    def __init__(self, requester: RazorRequester):
        self.requester = requester

    async def check_moodle(self, url: str) -> List[Dict[str, str]]:
        findings = []
        base_url = url.rstrip("/")
        for path in self.SENSITIVE_PATHS:
            target = f"{base_url}{path}"
            resp = await self.requester.fetch(target)
            # Jika status 200 dan isinya BUKAN halaman login/utama (Soft 404 check)
            if resp and resp.status_code == 200 and "Virtual Class Universitas Gunadarma" not in resp.text:
                findings.append({
                    "url": target,
                    "type": "Moodle Sensitive File Leak"
                })
        return findings

