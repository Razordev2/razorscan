import httpx

url = "https://smktarunabhakti.sch.id/xmlrpc.php"
payload = """<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"""

print("[*] Testing XML-RPC with POST request...")
try:
    with httpx.Client(verify=False) as client:
        resp = client.post(url, data=payload, headers={"Content-Type": "text/xml"})
        print(f"[+] Status: {resp.status_code}")
        print("[+] Response Body Preview:")
        print(resp.text[:500])
except Exception as e:
    print(f"[-] Error: {e}")
