import jwt
import json
import base64
from typing import Dict, Any, Optional, List

class JWTAnalyzer:
    @staticmethod
    def decode_unverified(token: str) -> Dict[str, Any]:
        try:
            # Decode header
            header_segment = token.split('.')[0]
            # Add padding
            header_segment += '=' * (4 - len(header_segment) % 4)
            header = json.loads(base64.b64decode(header_segment).decode('utf-8'))
            
            # Decode payload
            payload = jwt.decode(token, options={"verify_signature": False})
            
            return {
                "header": header,
                "payload": payload,
                "valid_format": True
            }
        except Exception as e:
            return {"valid_format": False, "error": str(e)}

    @staticmethod
    def analyze_issues(decoded: Dict[str, Any]) -> List[str]:
        issues = []
        header = decoded.get("header", {})
        payload = decoded.get("payload", {})

        if header.get("alg") == "none":
            issues.append("Algorithm set to 'none' (Critical)")
        
        if header.get("alg") == "HS256" and "kid" in header:
            issues.append("Possible Key ID (kid) injection point")

        if "exp" not in payload:
            issues.append("Token never expires")
            
        return issues

