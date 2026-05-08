import re
from typing import List, Dict
from razorscan.core.requester import RazorRequester

class CredentialHunter:
    # Nama file yang sering berisi kredensial atau backup
    TARGET_FILES = [
        "wp-config.php.bak", "wp-config.php.old", "wp-config.php.save",
        "wp-config.php~", ".wp-config.php.swp", "wp-config.txt",
        "database.sql", "db.sql", "data.sql", "backup.sql",
        "dump.sql", "site.zip", "backup.zip", "data.zip",
        ".env", ".env.old", ".env.bak", ".git/config",
        "akun.txt", "password.txt", "kredensial.xlsx", "data_user.xlsx",
        "user.pdf", "login.txt", "rahasia.txt"
    ]

    def __init__(self, requester: RazorRequester):
        self.requester = requester

    async def hunt(self, url: str) -> List[Dict[str, str]]:
        findings = []
        base_url = url.rstrip("/")
        
        # 1. Cek file sensitif di root
        for file in self.TARGET_FILES:
            target = f"{base_url}/{file}"
            resp = await self.requester.fetch(target)
            if resp and resp.status_code == 200:
                # Pastikan bukan halaman HTML biasa (Soft 404)
                if "text/html" not in resp.headers.get("Content-Type", "") or "<?php" in resp.text:
                    findings.append({
                        "url": target,
                        "type": "Potential Credential/Backup Leak"
                    })

        # 2. Cari di folder uploads (karena kita tahu ini open)
        uploads_url = f"{base_url}/wp-content/uploads/"
        resp = await self.requester.fetch(uploads_url)
        if resp and resp.status_code == 200:
            # Cari file menarik di directory listing menggunakan regex
            # Mencari ekstensi .sql, .zip, .bak, .xlsx, .pdf yang mencurigakan
            interesting = re.findall(r'href="([^"]+\.(?:sql|zip|bak|xlsx|pdf|txt|old))"', resp.text)
            for item in set(interesting):
                # Filter file gambar yang tidak sengaja terbawa regex
                if not any(ext in item.lower() for ext in [".jpg", ".png", ".gif", ".jpeg"]):
                    findings.append({
                        "url": f"{uploads_url}{item}",
                        "type": "Interesting File in Uploads Index"
                    })
                    
        return findings

