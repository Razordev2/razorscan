import httpx
import re

url = "https://smktarunabhakti.sch.id/wp-content/uploads/2024/01/"
print(f"Searching for interesting files in {url}...")

try:
    with httpx.Client(verify=False) as client:
        resp = client.get(url)
        if resp.status_code == 200:
            # Cari semua link file
            files = re.findall(r'href="([^"]+)"', resp.text)
            for f in set(files):
                # Lewati folder parent dan gambar
                if f.startswith("?") or any(ext in f.lower() for ext in [".png", ".jpg", ".jpeg", ".gif"]):
                    continue
                print(f"[!] FOUND: {url}{f}")
        else:
            print(f"Failed to access directory: {resp.status_code}")
except Exception as e:
    print(f"Error: {e}")
