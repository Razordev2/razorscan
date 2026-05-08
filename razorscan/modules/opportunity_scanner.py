import re
from typing import Dict, List, Any

class OpportunityScanner:
    # Mencari pola IP Internal (10.x, 172.16.x, 192.168.x)
    INTERNAL_IP_REGEX = r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)\d{1,3}\.\d{1,3}\b'
    
    # Kata kunci yang menandakan fitur administratif atau debug
    DANGER_KEYWORDS = [
        "admin", "debug", "config", "internal", "staging", "dev", 
        "root", "password", "secret", "token", "auth", "credential"
    ]

    # Parameter yang biasanya rentan IDOR / SSRF / LFI
    VULN_PARAMS = ["id", "uuid", "user", "file", "path", "url", "redirect", "dest", "cmd"]

    @staticmethod
    def analyze_content(content: str, url: str) -> Dict[str, Any]:
        findings = {
            "internal_ips": [],
            "keywords_found": [],
            "dangerous_params": [],
            "snippets": []
        }

        # Scan Internal IPs with Context
        ip_matches = re.finditer(OpportunityScanner.INTERNAL_IP_REGEX, content)
        for match in ip_matches:
            ip = match.group()
            findings["internal_ips"].append(ip)
            # Ambil 50 karakter sebelum dan sesudah untuk konteks
            start, end = max(0, match.start() - 50), min(len(content), match.end() + 50)
            findings["snippets"].append(f"IP [{ip}]: ...{content[start:end].strip()}...")

        # Scan Keywords with Context
        content_lower = content.lower()
        for kw in OpportunityScanner.DANGER_KEYWORDS:
            if kw in content_lower:
                findings["keywords_found"].append(kw)
                # Cari lokasi kata kunci tersebut
                idx = content_lower.find(kw)
                start, end = max(0, idx - 40), min(len(content), idx + 40)
                findings["snippets"].append(f"KW [{kw}]: ...{content[start:end].strip()}...")

        # Scan Parameters in current URL
        for param in OpportunityScanner.VULN_PARAMS:
            if f"{param}=" in url.lower():
                findings["dangerous_params"].append(param)

        return findings

