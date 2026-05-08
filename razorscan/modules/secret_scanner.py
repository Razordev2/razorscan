import re
from typing import Dict, List

class SecretScanner:
    # RegEx Patterns untuk mencari kredensial High-Severity
    PATTERNS = {
        "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
        "Firebase URL": r"https://[a-z0-9.-]+\.firebaseio\.com",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "Generic Secret": r"(?i)(key|secret|token|auth|password|passwd|pwd|bearer|access_key)\s*[:=]\s*['\"]([a-zA-Z0-9-_=]{16,})['\"]",
        "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
        "Authorization Header": r"(?i)Authorization:\s*Bearer\s+[a-zA-Z0-9\._\-]+",
        "Private IP": r"172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}"
    }

    @staticmethod
    def scan(content: str) -> Dict[str, List[str]]:
        findings = {}
        for name, pattern in SecretScanner.PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                # Membersihkan hasil jika ada grup dalam regex
                clean_matches = []
                for m in matches:
                    if isinstance(m, tuple):
                        clean_matches.append(m[1]) # Ambil rahasianya saja
                    else:
                        clean_matches.append(m)
                findings[name] = list(set(clean_matches))
        return findings

