# 🛡️ Outpost — Attack Surface Analyzer

Outpost is an AI-assisted reconnaissance analysis tool that turns raw
scan data into a prioritized, scored security report. Paste Nmap output
(or run a live header check) and Outpost identifies weaknesses, ranks
them by severity, explains each one, and assigns an overall security
grade from **A to F**.

Built for **authorized security testing and education** — for example,
reviewing systems you own or public practice targets like
`scanme.nmap.org` and `zero.webappsecurity.com`.

## 🔗 Live Demo

> Deployed on Streamlit Community Cloud: **[add your app link here after deploying]**

## ✨ What it does

- Analyzes pasted **Nmap output** or performs a single authorized **HTTP header check**
- Detects **7 categories** of risk: outdated software, exposed ports,
  unencrypted HTTP, missing security headers, weak TLS, information
  disclosure, and OS fingerprinting
- Maps findings to **OWASP Top 10** and **CWE** concepts
- Assigns a **severity-weighted score (0–100, Grade A–F)**
- Exports a downloadable **Markdown report**

## 🚫 What it does NOT do

Outpost is a **passive, defensive** tool. It performs no port scanning,
brute forcing, or exploitation — the live check is a single standard
HTTP GET request, the same as opening a page in a browser. The user
must confirm authorization before any analysis runs.

## 🧰 Tech Stack

- **Python** + **Streamlit** (UI and app logic)
- **requests** (live header check)
- Rule-based detection & scoring engine

## ▶️ Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

Then open the local URL Streamlit prints (usually http://localhost:8501).

## Deploy on Streamlit Community Cloud

1. Push this repo to GitHub (see steps below)
2. Go to **share.streamlit.io** → sign in with GitHub → **New app**
3. Select your repo, branch (`main`), and main file `app.py`
4. Click **Deploy** — you'll get a public link to share

## Project Structure

```
outpost/
├── app.py              # Streamlit app + analysis engine
├── requirements.txt    # Python dependencies
└── README.md
```

## Ethical Use

This tool is for authorized testing and education only. Any
vulnerability found in a real system should be disclosed responsibly to
the affected organization.

---
*Educational prototype — not a substitute for a professional penetration test.*
