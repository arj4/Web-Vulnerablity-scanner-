
# Web vulnerablity scanner  (Streamlit)

A tiny, **educational** web testing helper built with Streamlit. It performs a few very basic checks against a target web app:

- Probes for intentionally vulnerable apps: **DVWA**, **Mutillidae**, **phpMyAdmin** (via known paths)
- Tries minimal **SQL injection** error checks
- Tries simple **reflected XSS** checks in GET parameters

> ⚠️ **Ethical Use Only**  
> Use this tool only on systems you own or have **explicit permission** to test. You are responsible for your actions.

---

## My Setup (Example)

In my case, I used a **Metasploitable** server running in a VM on my local network.  
The Streamlit page expects you to input the **IP address (or URL)** of the Metasploitable machine running on your LAN, e.g.:

- `http://192.168.0.50`
- `http://192.168.0.50:8080`

---

## Features

- 🧭 Detects common lab apps by requesting well-known paths
- 🧪 Quick SQLi probes that look for DB error signatures
- 💬 Simple reflected XSS checks (payload reflection)
- 🪶 Lightweight one-page Streamlit UI



---

## Requirements

- Python 3.8+
- Packages:
  - `streamlit`
  - `requests`

Install with:


pip install -r requirements.txt





## Getting Started

1. Place `wpt.py` in a folder (or clone this repo).

2. Install dependencies (see above).

3. Run the app:

  
   streamlit run wpt.py


4. In the UI, enter your **target base URL** (e.g., your Metasploitable VM):

   * `http://192.168.0.50`
   * or include a port/path: `http://192.168.0.50:80/`
  
        <img width="1438" height="466" alt="Screenshot 2025-10-07 at 1 57 53 AM" src="https://github.com/user-attachments/assets/1e8a1418-6d32-4fd7-bb3c-d7b307434feb" />


5. Click Scan to run the checks.

---

## Example Targets (Metasploitable on LAN)

* `http://<metasploitable-ip>`
* `http://<metasploitable-ip>/dvwa/`
* `http://<metasploitable-ip>/mutillidae/`
* `http://<metasploitable-ip>/phpmyadmin/`

> Paths can vary by image/version—adjust to what exists on your VM.

---

## What It Does (High-Level)

* App presence checks:** request paths like `/dvwa/`, `/mutillidae/`, `/phpmyadmin/` and mark as found if responses match expected traits.
* SQLi checks:** append a few error-triggering payloads (e.g., `' or 1=1 --`) to query params and look for DB error text (e.g., *You have an error in your SQL syntax*, *mysql_fetch* warnings).
* Reflected XSS checks:** inject simple `<script>alert(1)</script>`-style payloads and see if they reflect in the response.


  <img width="888" height="583" alt="Screenshot 2025-10-07 at 2 14 32 AM" src="https://github.com/user-attachments/assets/0d0f7855-5af1-49b6-97ba-3015804bde3c" />


                             Vulnerablities being detected 
---

## Limitations

* Not a replacement for tools like **Burp**, **OWASP ZAP**, or **Nuclei**
* Probes only a few paths with simple payloads
* Focuses on GET parameters; no form crawling or auth handling
* No rate limiting or WAF evasion
* Intended for **local labs & learning**, not production pentests

---

## Troubleshooting

* Nothing detected:** verify the URL is correct/reachable (open it in a browser). Paths may differ.
* SSL issues:** for self-signed lab certs, prefer HTTP or configure verification appropriately (not recommended outside labs).
* Timeouts:** the target may be down or filtered—check network reachability.
* Non-standard ports:** try `http://<ip>:<port>`.

---

