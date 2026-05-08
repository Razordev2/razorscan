import asyncio
import re
from typing import List, Dict, Any
from razorscan.core.requester import RazorRequester

class WordPressHunter:
    def __init__(self, requester: RazorRequester):
        self.requester = requester
        self.plugins = [
            "elementor", "contact-form-7", "woocommerce", "wp-rocket", 
            "revslider", "js_composer", "mailchimp-for-wp", "all-in-one-seo-pack",
            "duplicator", "wp-file-manager", "wp-query-console", "post-carousel"
        ]

    async def check_wordpress(self, url: str) -> List[Dict[str, str]]:
        findings = []
        
        # 1. Check User Enumeration
        user_url = f"{url.rstrip('/')}/wp-json/wp/v2/users"
        resp = await self.requester.fetch(user_url)
        if resp and resp.status_code == 200:
            try:
                users = resp.json()
                for user in users:
                    findings.append({
                        "type": "WP User Found",
                        "detail": f"ID: {user.get('id')} | Name: {user.get('slug')}",
                        "url": user_url
                    })
            except:
                pass

        # 2. Check XML-RPC
        xml_url = f"{url.rstrip('/')}/xmlrpc.php"
        resp = await self.requester.fetch(xml_url, method="POST", data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>')
        if resp and "system.listMethods" in resp.text:
            findings.append({
                "type": "XML-RPC Enabled",
                "detail": "Vulnerable to Brute Force & Pingback DDoS",
                "url": xml_url
            })

        # 3. Check for exposed plugins (Passive)
        # We look for common plugin paths in the homepage
        resp = await self.requester.fetch(url)
        if resp:
            for plugin in self.plugins:
                if f"/wp-content/plugins/{plugin}/" in resp.text:
                    findings.append({
                        "type": "WP Plugin Detected",
                        "detail": f"Plugin: {plugin} (Check for CVEs)",
                        "url": f"{url.rstrip('/')}/wp-content/plugins/{plugin}/"
                    })

        # 4. Check for Version
        version_match = re.search(r'content="WordPress (\d+\.\d+\.\d+)"', resp.text if resp else "")
        if version_match:
            findings.append({
                "type": "WP Version Leak",
                "detail": f"Version: {version_match.group(1)}",
                "url": url
            })

        return findings

