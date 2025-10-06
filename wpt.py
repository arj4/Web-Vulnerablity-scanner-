#!/usr/bin/env python3
"""
streamlit_vuln_scanner.py

A Streamlit application to detect common MetaSploitable2 web
vulnerabilities (DVWA SQLi & XSS, Mutillidae, phpMyAdmin) as well
as generic SQL Injection and Reflected XSS tests on any GET-based URL.

Usage:
    streamlit run streamlit_vuln_scanner.py
"""

import streamlit as st
import requests
import urllib.parse
import time

# suppress insecure request warnings
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Generic payloads & error patterns
SQL_PAYLOADS = [
    "' OR 1=1 -- ",
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR '1'='1';--",
    "\" OR \"\" = \"",
]
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query(",
    "sqlstate",
]
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "\"><script>alert('xss')</script>",
    "'\"><img src=x onerror=alert('xss')>",
]

# Known MetaSploitable2 app endpoints
MS2_APPS = {
    "DVWA SQL Injection": "/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit",
    "DVWA Reflected XSS": "/dvwa/vulnerabilities/xss_r/?name=test&Submit=Submit",
    "Mutillidae": "/mutillidae/",
    "phpMyAdmin": "/phpMyAdmin/",
}

def fetch(url, cookies=None):
    """Fetch a URL, optionally sending cookies."""
    headers = {}
    if cookies:
        headers["Cookie"] = cookies
    try:
        return requests.get(url, headers=headers, timeout=10, verify=False)
    except Exception as e:
        st.write(f"[!] Request error: {e}")
        return None

def detect_metasploitable2(base_url, cookies=None):
    """
    Probe for known MetaSploitable2 web apps.
    Returns a dict of {app_name: full_url} for each detected.
    """
    st.subheader("🔍 Detecting MetaSploitable2 Applications")
    detected = {}
    for name, path in MS2_APPS.items():
        url = urllib.parse.urljoin(base_url, path)
        resp = fetch(url, cookies)
        if resp and resp.status_code == 200:
            st.info(f"Detected **{name}** at `{path}`")
            detected[name] = url
    if not detected:
        st.warning("No MetaSploitable2-specific apps detected.")
    return detected

def test_sqli(base_url, params, cookies=None):
    st.subheader("🛠️ SQL Injection Tests")
    # build baseline URL
    parsed = list(urllib.parse.urlparse(base_url))
    parsed[4] = urllib.parse.urlencode(params, doseq=True)
    baseline_url = urllib.parse.urlunparse(parsed)
    # measure baseline
    start = time.time()
    base_resp = fetch(baseline_url, cookies)
    baseline = time.time() - start if base_resp else None

    for param in params:
        for payload in SQL_PAYLOADS:
            attack_params = params.copy()
            attack_params[param] = attack_params[param][0] + payload
            parsed[4] = urllib.parse.urlencode(attack_params, doseq=True)
            attack_url = urllib.parse.urlunparse(parsed)
            st.write(f"- Testing `{param}` with payload `{payload.strip()}`")
            start = time.time()
            resp = fetch(attack_url, cookies)
            delta = (time.time() - start - (baseline or 0)) if baseline else None

            if resp:
                content = resp.text.lower()
                if any(err in content for err in SQL_ERRORS):
                    st.error(f"[Error-based SQLi] `{param}` vulnerable!\n{attack_url}")
                elif delta and delta > 4:
                    st.error(f"[Time-based SQLi] `{param}` delay {delta:.1f}s!\n{attack_url}")
                else:
                    st.success(f"No SQLi detected on `{param}`.")

def test_xss(base_url, params, cookies=None):
    st.subheader("🌐 Reflected XSS Tests")
    parsed = list(urllib.parse.urlparse(base_url))
    parsed[4] = urllib.parse.urlencode(params, doseq=True)

    for param in params:
        for payload in XSS_PAYLOADS:
            attack_params = params.copy()
            attack_params[param] = attack_params[param][0] + payload
            parsed[4] = urllib.parse.urlencode(attack_params, doseq=True)
            attack_url = urllib.parse.urlunparse(parsed)
            st.write(f"- Testing `{param}` with payload `{payload}`")
            resp = fetch(attack_url, cookies)
            if resp and payload.lower() in resp.text.lower():
                st.error(f"[Reflected XSS] `{param}` vulnerable!\n{attack_url}")
            else:
                st.success(f"No XSS detected on `{param}`.")

def main():
    st.title("🛡️ MetaSploitable2 & Generic Web Vulnerability Scanner")
    st.warning("**Warning:** Only scan servers you have explicit permission to test.")

    root = st.text_input("Enter base URL (e.g., http://192.168.50.180/)", "")
    cookies = st.text_input(
        "Optional: Cookie header for authenticated apps (e.g. phpMyAdmin session)", ""
    )

    if st.button("Detect & Scan"):
        if not root:
            st.error("Please enter a target base URL.")
            return

        # 1) Detect MetaSploitable2 apps
        apps = detect_metasploitable2(root, cookies)

        # 2) For each detected MS2 app, run appropriate tests
        for name, app_url in apps.items():
            params = urllib.parse.parse_qs(urllib.parse.urlparse(app_url).query)
            if "SQL Injection" in name:
                st.header(f"⚙️ Scanning {name}")
                test_sqli(app_url, params, cookies)
            elif "XSS" in name:
                st.header(f"⚙️ Scanning {name}")
                test_xss(app_url, params, cookies)
            else:
                st.header(f"ℹ️ {name} detected at {app_url}")
                st.info("Known to be vulnerable out-of-the-box. "
                        "Visit this path in your browser to explore.")

        # 3) If no MS2 apps, fallback to generic scan on any URL with query params
        if not apps:
            parsed = urllib.parse.urlparse(root)
            if not parsed.query:
                st.error("No query parameters found for generic scan. Try adding `?id=1` etc.")
                return
            params = urllib.parse.parse_qs(parsed.query)
            st.header("⚙️ Running generic vulnerability tests")
            test_sqli(root, params, cookies)
            test_xss(root, params, cookies)

        st.success("All scans completed.")

if __name__ == "__main__":
    main()
