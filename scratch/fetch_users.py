import httpx
import json

url = "https://smktarunabhakti.sch.id/wp-json/wp/v2/users"
try:
    with httpx.Client(verify=False) as client:
        resp = client.get(url)
        if resp.status_code == 200:
            print(json.dumps(resp.json(), indent=2))
        else:
            print(f"Error: {resp.status_code}")
except Exception as e:
    print(f"Exception: {e}")
