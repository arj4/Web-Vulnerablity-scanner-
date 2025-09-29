#!/usr/bin/env python3
"""
Mini web testing tool built with Streamlit.

Scans a target for:
- DVWA, Mutillidae, phpMyAdmin
- Simple SQLi and reflected XSS in GET parameters

Usage:
    streamlit run wpt.py
"""

import streamlit as st
import requests
import urllib.parse
import time

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Test data
INJECTION_STRINGS = [
    "' OR 1=1 -- ",
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR '1'='1';--",
    '" OR "" = "',
]

ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query(",
    "sqlstate",
]

XSS_STRINGS = [
    "<script>alert('x')</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg/onload=alert(1337)>",
]

HEADERS = {"User-Agent": "Mozilla/5.0"}

def check_page(url, keyword):
    try:
        r = requests.get(url, headers=HEADERS, timeout=5, verify=False)
        return keyword.lower() in r.text.lower()
    except:
        return False

def test_sql(url):
    if "?" not in url:
        return False
    base, params = url.split("?", 1)
    for payload in INJECTION_STRINGS:
        new_params = urllib.parse.parse_qs(params)
        for k in new_params:
            new_params[k] = payload
        new_url = f"{base}?{urllib.parse.urlencode(new_params, doseq=True)}"
        try:
            resp = requests.get(new_url, headers=HEADERS, timeout=5, verify=False)
            if any(err in resp.text.lower() for err in ERROR_PATTERNS):
                return new_url
        except:
            continue
    return False

def test_xss(url):
    if "?" not in url:
        return False
    base, params = url.split("?", 1)
    for payload in XSS_STRINGS:
        new_params = urllib.parse.parse_qs(params)
        for k in new_params:
            new_params[k] = payload
        new_url = f"{base}?{urllib.parse.urlencode(new_params, doseq=True)}"
        try:
            resp = requests.get(new_url, headers=HEADERS, timeout=5, verify=False)
            if payload in resp.text:
                return new_url
        except:
            continue
    return False

st.title("Web Vulnerability Scanner")

target = st.text_input("Target URL (e.g., http://192.168.1.100/)")

if st.button("Run Scan") and target:
    if not target.endswith("/"):
        target += "/"

    st.write("Scanning...")
    time.sleep(0.5)

    # Common paths
    checks = {
        "DVWA": "dvwa",
        "Mutillidae": "mutillidae",
        "phpMyAdmin": "phpmyadmin",
    }

    for name, path in checks.items():
        if check_page(target + path, path):
            st.success(f"{name} found at {target + path}")

    sql_result = test_sql(target)
    if sql_result:
        st.error(f"Possible SQL Injection at: {sql_result}")

    xss_result = test_xss(target)
    if xss_result:
        st.error(f"Possible XSS at: {xss_result}")

    st.write("Scan completed.")
