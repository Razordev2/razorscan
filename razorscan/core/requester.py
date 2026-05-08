import asyncio
import httpx
import socket
from typing import Optional, Dict, Any
from rich.console import Console

console = Console()

class RazorRequester:
    def __init__(self, timeout: int = 15, proxy: Optional[str] = None, delay: float = 0.5):
        self.timeout = timeout
        self.proxy = proxy
        self.delay = delay
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        }

    def is_alive(self, domain: str) -> bool:
        """Cek apakah domain bisa di-resolve ke IP."""
        try:
            domain_only = domain.replace("https://", "").replace("http://", "").split("/")[0]
            socket.gethostbyname(domain_only)
            return True
        except socket.gaierror:
            return False

    async def fetch(self, url: str, method: str = "GET", **kwargs) -> Optional[httpx.Response]:
        """
        Asynchronous request handler with safety delays.
        """
        async with httpx.AsyncClient(
            timeout=self.timeout, 
            proxy=self.proxy, 
            verify=False,
            follow_redirects=True
        ) as client:
            try:
                await asyncio.sleep(self.delay)
                
                # Merge default headers with custom ones from kwargs
                request_headers = self.headers.copy()
                if "headers" in kwargs:
                    request_headers.update(kwargs.pop("headers"))
                
                response = await client.request(
                    method, 
                    url, 
                    headers=request_headers, 
                    **kwargs
                )
                if response.status_code != 200:
                    console.print(f"[dim][yellow]![/yellow] {url} returned {response.status_code}[/dim]")
                return response
            except Exception as e:
                console.print(f"[dim][red]![/red] Error fetching {url}: {str(e)}[/dim]")
                return None

    async def get_json(self, url: str) -> Optional[Dict[str, Any]]:
        resp = await self.fetch(url)
        if resp and "application/json" in resp.headers.get("Content-Type", ""):
            return resp.json()
        return None

