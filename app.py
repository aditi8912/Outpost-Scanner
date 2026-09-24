"""
Outpost — Attack Surface Analyzer (Streamlit edition)
An AI-assisted reconnaissance analysis tool that turns raw scan data
(Nmap output or a single authorized HTTP header check) into a
prioritized, scored security report.

For authorized security testing and education only. Performs no port
scanning, brute forcing, or exploitation — the live check is a single
standard HTTP GET request, the same as opening a page in a browser.
"""

import re
import datetime
import requests
import streamlit as st

st.set_page_config(page_title="Outpost — Attack Surface Analyzer", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root{--ink:#0F1B2D;--muted:#55627A;--faint:#93A0B4;--accent:#1B4B91;--accent-dk:#0F2F5C;--teal:#0E9488;--teal-lt:#7EEAD8;--border:#E1E6ED;--card:#FBFCFE;}
.stApp{background:radial-gradient(1100px 500px at 12% -8%,rgba(27,75,145,.05),transparent 60%),radial-gradient(900px 460px at 100% 0%,rgba(14,148,136,.045),transparent 55%),#F4F7FB;}
html,body,[class*="css"]{font-family:'Inter',sans-serif;color:var(--ink);}
#MainMenu,header[data-testid="stHeader"],footer{visibility:hidden;}
.block-container{padding-top:1.1rem;padding-bottom:2rem;max-width:1220px;}
.stApp::before{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;background-image:radial-gradient(circle,rgba(27,75,145,.06) 1px,transparent 1px);background-size:26px 26px;-webkit-mask-image:radial-gradient(ellipse 65% 50% at 18% 0%,black 12%,transparent 72%);mask-image:radial-gradient(ellipse 65% 50% at 18% 0%,black 12%,transparent 72%);}
.hero{position:relative;overflow:hidden;z-index:1;background:linear-gradient(135deg,#0F2F5C 0%,#14396E 52%,#0E9488 170%);border:1px solid #123A6B;border-radius:16px;padding:24px 30px;margin-bottom:22px;display:flex;align-items:center;gap:30px;box-shadow:0 18px 40px -20px rgba(14,45,92,.75);}
.hero::before{content:'';position:absolute;inset:0;opacity:.55;background-image:linear-gradient(rgba(255,255,255,.06) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.06) 1px,transparent 1px);background-size:32px 32px;-webkit-mask-image:linear-gradient(90deg,black,transparent 88%);mask-image:linear-gradient(90deg,black,transparent 88%);animation:drift 16s linear infinite;}
@keyframes drift{from{background-position:0 0,0 0}to{background-position:32px 32px,32px 32px}}
.hero-scan{position:absolute;top:0;bottom:0;width:140px;background:linear-gradient(90deg,transparent,rgba(126,234,216,.22),transparent);filter:blur(3px);transform:skewX(-16deg);animation:beam 5.5s ease-in-out infinite;}
@keyframes beam{0%{left:-15%}55%{left:115%}100%{left:115%}}
.radar{position:relative;width:104px;height:104px;flex-shrink:0;}
.radar .ring{position:absolute;border-radius:50%;border:1px solid rgba(126,234,216,.4);inset:0;}
.radar .ring.r2{inset:18px;opacity:.7}.radar .ring.r3{inset:36px;opacity:.5}
.radar .cross-h,.radar .cross-v{position:absolute;background:rgba(126,234,216,.25)}
.radar .cross-h{left:0;right:0;top:50%;height:1px}.radar .cross-v{top:0;bottom:0;left:50%;width:1px}
.radar .sweep{position:absolute;inset:0;border-radius:50%;background:conic-gradient(from 0deg,rgba(126,234,216,.6),transparent 72%);animation:spin 3.1s linear infinite;-webkit-mask:radial-gradient(circle,transparent 5px,black 6px);mask:radial-gradient(circle,transparent 5px,black 6px);}
@keyframes spin{to{transform:rotate(360deg)}}
.radar .blip{position:absolute;width:7px;height:7px;border-radius:50%;background:var(--teal-lt);box-shadow:0 0 9px var(--teal-lt);opacity:0}
.radar .b1{top:24px;left:62px;animation:blip 3.1s linear infinite}
.radar .b2{top:60px;left:34px;animation:blip 3.1s linear infinite 1.4s}
@keyframes blip{0%,100%{opacity:0;transform:scale(.5)}12%{opacity:1;transform:scale(1)}55%{opacity:.15}}
.hero-copy{position:relative;z-index:1}
.hero-kicker{font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:2.5px;color:var(--teal-lt);margin-bottom:7px}
.hero-title{font-family:'Space Grotesk',sans-serif;font-size:25px;font-weight:700;line-height:1.15;color:#fff}
.hero-sub{font-size:13px;color:#A9C6E8;margin-top:8px;max-width:560px}
.hero-badges{margin-top:14px;display:flex;gap:10px;flex-wrap:wrap}
.hero-badge{font-family:'JetBrains Mono',monospace;font-size:10.5px;color:#CFE6FF;background:rgba(255,255,255,.09);border:1px solid rgba(255,255,255,.16);padding:4px 10px;border-radius:999px}
.sec-head{font-family:'Space Grotesk',sans-serif;font-size:14px;font-weight:600;letter-spacing:.3px;color:var(--ink);display:flex;align-items:center;gap:8px;margin-bottom:4px}
.sec-head::before{content:'';width:8px;height:8px;border-radius:2px;background:var(--teal)}
.stTextInput input,.stTextArea textarea{border-radius:8px !important;border:1px solid #C9D2DE !important;font-family:'JetBrains Mono',monospace !important;font-size:13px !important;background:#FCFDFF !important;}
.stTextInput input:focus,.stTextArea textarea:focus{border-color:var(--accent) !important;box-shadow:0 0 0 3px #EAF1FB !important}
.stButton button[kind="primary"]{background:var(--accent) !important;border:none !important;border-radius:8px !important;font-weight:600 !important;padding:.55rem 1rem !important;box-shadow:0 6px 16px -8px rgba(27,75,145,.6) !important;}
.stButton button[kind="primary"]:hover{background:#163C74 !important}
.stButton button[kind="secondary"]{border-radius:8px !important;border:1px solid #C9D2DE !important;color:var(--muted) !important;font-weight:500 !important}
.stDownloadButton button{border-radius:8px !important;border:1px solid #C9D2DE !important;font-weight:600 !important}
.score-num{font-family:'Space Grotesk',sans-serif;font-size:46px;font-weight:700;line-height:1}
.grade-pill{display:inline-block;font-family:'Space Grotesk',sans-serif;font-weight:700;font-size:13px;padding:3px 12px;border-radius:999px;margin-top:4px}
.sevbox{text-align:center;padding:8px 4px;border:1px solid var(--border);border-radius:9px;background:var(--card)}
.sevbox .n{font-family:'Space Grotesk',sans-serif;font-size:20px;font-weight:700;line-height:1}
.sevbox .l{font-size:10px;color:var(--faint);margin-top:2px}
[data-testid="stExpander"]{border:1px solid var(--border) !important;border-radius:10px !important;margin-bottom:10px !important;background:var(--card) !important;box-shadow:0 1px 2px rgba(16,25,43,.04) !important;overflow:hidden;}
[data-testid="stExpander"] summary{font-weight:600 !important;font-size:13.5px !important;padding:4px 2px !important}
[data-testid="stExpander"] summary:hover{color:var(--accent) !important}
.sev-badge{display:inline-block;font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:600;letter-spacing:.4px;padding:3px 9px;border-radius:5px;text-transform:uppercase}
.ethics{background:#EAF1FB;border:1px solid #CFE0F5;border-radius:10px;padding:12px 15px;font-size:12.5px;color:#1E3E68;margin-bottom:14px;line-height:1.5}
.ethics b{color:var(--accent-dk)}
.small-note{color:var(--faint);font-size:11.5px;line-height:1.6}
.small-note b{color:var(--muted)}
[data-testid="stSidebar"]{background:#fff;border-right:1px solid var(--border)}
.stProgress > div > div > div{background:linear-gradient(90deg,var(--accent),var(--teal)) !important}
</style>
""", unsafe_allow_html=True)

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 26, "high": 16, "medium": 8, "low": 3, "info": 0}
SEV_COLOR = {"critical": "#C7384A", "high": "#C96A22", "medium": "#B4870F", "low": "#2E6FD6", "info": "#7C8AA0"}

RISKY_PORTS = {
    21:("FTP","high","Often transmits credentials in plaintext; use SFTP/FTPS or disable."),
    23:("Telnet","critical","Unencrypted remote administration protocol. Replace with SSH."),
    25:("SMTP","low","Confirm open relay is disabled and authentication is enforced."),
    445:("SMB","high","Historically targeted by worms (EternalBlue-class). Restrict to internal networks."),
    1433:("MSSQL","high","Database port should not be internet-facing."),
    3306:("MySQL","high","Database port should not be internet-facing."),
    3389:("RDP","critical","Frequently targeted by brute-force and ransomware. Restrict via VPN + MFA."),
    5432:("PostgreSQL","high","Database port should not be internet-facing."),
    6379:("Redis","critical","Frequently deployed with no authentication; common ransomware entry point."),
    27017:("MongoDB","critical","Frequently deployed with no authentication and exposed publicly."),
    9200:("Elasticsearch","high","Exposed instances commonly scraped for data; should not be public."),
}
SOFTWARE_RULES = [
    (r"Apache(?:/| httpd/?)\s?([\d.]+)","Apache HTTP Server","2.4.58","medium","CVE-2014-0117 / CVE-2021-44224 (version-dependent)","Older Apache builds carry multiple historical CVEs (DoS, info leak, SSRF-class)."),
    (r"nginx/([\d.]+)","nginx","1.25.0","medium","Varies by version","Older nginx builds may miss patches for HTTP/2 and request-smuggling issues."),
    (r"Microsoft-IIS/([\d.]+)","Microsoft IIS","10.0","medium","Varies by version","Legacy IIS versions are frequently unsupported and missing critical patches."),
    (r"(?:X-Powered-By:\s*)?PHP/([\d.]+)","PHP","8.1.0","high","Multiple (EOL branches)","PHP below 8.1 is end-of-life and no longer receives security patches."),
    (r"Tomcat/?([\d.]+)","Apache Tomcat","9.0.80","medium","Varies by version","Older Tomcat builds have known deserialization and info-disclosure issues."),
    (r"jquery[-.]?([\d.]+)(?:\.min)?\.js","jQuery","3.5.0","medium","CVE-2020-11022 / CVE-2020-11023 (XSS)","jQuery before 3.5 has documented XSS vulnerabilities in HTML methods."),
    (r"OpenSSL/([\d.]+)","OpenSSL","3.0.0","high","Multiple (Heartbleed-class on 1.0.1)","Legacy OpenSSL 1.0.x is past end-of-life and may be vulnerable to critical flaws."),
]

def version_less(a, b):
    pa = [int(x) for x in a.split(".") if x.isdigit()]
    pb = [int(x) for x in b.split(".") if x.isdigit()]
    for i in range(max(len(pa), len(pb))):
        x = pa[i] if i < len(pa) else 0
        y = pb[i] if i < len(pb) else 0
        if x < y: return True
        if x > y: return False
    return False

def first_match(text, pattern):
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(0).strip()[:160] if m else ""

def analyze(text):
    findings = []
    t = text or ""
    if (re.search(r"http://\S+", t, re.I) or re.search(r"^GET .* HTTP", t, re.I | re.M)) and not re.search(r"https://\S+", t, re.I):
        findings.append(dict(sev="medium", title="Unencrypted HTTP communication observed", meta="Transport layer",
            desc="The data references plain HTTP rather than HTTPS. Traffic — including any form or login data — can travel unencrypted and be read on the network path.",
            evidence=first_match(t, r"http://\S+"), fix="Enforce HTTPS site-wide with a redirect from HTTP, and enable HSTS."))
    for m in re.finditer(r"(\d{1,5})/tcp\s+open\s+(\S+)", t, re.I):
        port = int(m.group(1))
        if port in RISKY_PORTS:
            name, sev, note = RISKY_PORTS[port]
            findings.append(dict(sev=sev, title=f"Exposed {name} service on port {port}", meta=f"Port {port}/tcp — {m.group(2)}",
                desc=f"Port {port} ({name}) was reported open. {note}", evidence=m.group(0),
                fix=f"Restrict port {port} to trusted internal networks, or disable it if unused."))
    for pattern, name, min_safe, sev, cve, note in SOFTWARE_RULES:
        m = re.search(pattern, t, re.I)
        if m and m.group(1) and version_less(m.group(1), min_safe):
            findings.append(dict(sev=sev, title=f"Outdated {name} detected (v{m.group(1)})", meta="Detected via banner/signature match",
                desc=note, evidence=m.group(0), cve=cve, fix=f"Upgrade {name} to {min_safe} or later and apply vendor security patches."))
    if re.search(r"HTTP/1\.[01]\s+\d{3}", t) or re.search(r"^Server:", t, re.M) or re.search(r"^Content-Type:", t, re.M):
        for pat, name, sev, desc in [
            (r"strict-transport-security","Strict-Transport-Security","medium","No HSTS header — browsers won't be forced to use HTTPS, allowing downgrade attacks."),
            (r"content-security-policy","Content-Security-Policy","medium","No CSP header — no policy restricting which scripts can run, raising XSS impact."),
            (r"x-content-type-options","X-Content-Type-Options","low","No X-Content-Type-Options header — browsers may MIME-sniff responses."),
            (r"x-frame-options","X-Frame-Options","low","No X-Frame-Options header — the page may be vulnerable to clickjacking."),
        ]:
            if not re.search(pat, t, re.I):
                findings.append(dict(sev=sev, title=f"Missing security header: {name}", meta="HTTP response headers",
                    desc=desc, evidence="(not present in supplied header dump)", fix=f"Add the {name} header to server responses."))
    if re.search(r"(stack trace|error report|tomcat/[\d.]+ - error|fatal error:|whitelabel error page)", t, re.I):
        findings.append(dict(sev="low", title="Verbose error message may disclose server details", meta="Information disclosure",
            desc="The data contains a raw error page. These often reveal exact software versions or internal paths useful to an attacker.",
            evidence=first_match(t, r".{0,40}(error report|stack trace|fatal error:).{0,40}"),
            fix="Configure generic custom error pages and disable verbose/debug output."))
    m = re.search(r"(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)\b", t, re.I)
    if m:
        findings.append(dict(sev="high", title=f"Legacy TLS/SSL protocol referenced ({m.group(1)})", meta="Transport layer security",
            desc="Older SSL/TLS versions have known cryptographic weaknesses and are deprecated.",
            evidence=first_match(t, r".{0,30}(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1).{0,30}"),
            fix="Disable protocols below TLS 1.2 and support TLS 1.3 where possible."))
    m = re.search(r"OS(?: details| guesses)?:\s*([^\n]+)", t, re.I) or re.search(r"Running \(JUST GUESSING\):\s*([^\n]+)", t, re.I)
    if m:
        findings.append(dict(sev="info", title="Operating system fingerprint identified", meta="Host fingerprinting",
            desc=f"Reconnaissance data reveals a probable OS fingerprint ({m.group(1).strip()}). Not a vulnerability itself, but it narrows which exploits apply.",
            evidence=m.group(0), fix="No direct action required; treat as context for prioritizing other findings."))
    findings.sort(key=lambda f: SEV_ORDER.index(f["sev"]))
    return findings

def score_findings(findings):
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[f["sev"]] += 1
    value = max(0, 100 - sum(SEV_WEIGHT[f["sev"]] for f in findings))
    grade = "A" if value >= 90 else "B" if value >= 75 else "C" if value >= 55 else "D" if value >= 35 else "F"
    return value, grade, counts

def live_check(target):
    target = target.strip()
    schemes = [target] if target.startswith(("http://", "https://")) else [f"https://{target}", f"http://{target}"]
    last_err = None
    for url in schemes:
        try:
            r = requests.get(url, timeout=7, headers={"User-Agent": "Outpost-Analyzer/1.0 (authorized-check)"})
            lines = [f"Fetched URL: {r.url}", f"HTTP/1.1 {r.status_code} {r.reason}"]
            lines += [f"{k}: {v}" for k, v in r.headers.items()]
            lines += ["", "--- body excerpt ---", r.text[:4000]]
            return True, r.status_code, r.url, "\n".join(lines)
        except Exception as e:
            last_err = str(e)
    return False, None, None, f"LIVE FETCH ERROR: {last_err}"

def build_markdown(target, findings, value, grade, live_info):
    md = ["# Outpost Attack Surface Report", "", f"**Target:** {target}", "",
          f"**Generated:** {datetime.datetime.utcnow().isoformat()}Z", "",
          f"**Score:** {value}/100 (Grade {grade})", ""]
    if live_info:
        md += [f"**Live check:** {live_info}", ""]
    md += ["---", ""]
    if not findings:
        md += ["No findings matched for the supplied data."]
    for f in findings:
        md += [f"## [{f['sev'].upper()}] {f['title']}", "", f"**Context:** {f['meta']}", "", f["desc"], ""]
        if f.get("evidence"):
            md += ["**Evidence:**", "```", f["evidence"], "```", ""]
        if f.get("cve"):
            md += [f"**Reference:** {f['cve']}", ""]
        md += [f"**Recommended fix:** {f['fix']}", "", "---", ""]
    return "\n".join(md)

SAMPLE = """Starting Nmap 7.99 at 2026-08-31
Nmap scan report for zero.webappsecurity.com (192.0.2.44)
Not shown: 997 filtered tcp ports
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 2.3.4
80/tcp   open  http     Apache/2.4.7 (Ubuntu)
3306/tcp open  mysql    MySQL 5.5.62
Running (JUST GUESSING): Linux 5.X
OS details: Linux 5.4 - 5.15

--- curl -I http://zero.webappsecurity.com/ ---
HTTP/1.1 200 OK
Server: Apache/2.4.7 (Ubuntu)
Content-Type: text/html; charset=UTF-8
X-Powered-By: PHP/5.6.40

--- page source excerpt ---
<script src="/js/jquery-1.8.2.min.js"></script>

--- error triggered on /search.html ---
<html><head><title>Apache Tomcat/7.0.70 - Error report</title>"""

st.markdown("""
<div class="hero">
  <div class="hero-scan"></div>
  <div class="radar">
    <span class="ring"></span><span class="ring r2"></span><span class="ring r3"></span>
    <span class="cross-h"></span><span class="cross-v"></span>
    <span class="sweep"></span><span class="blip b1"></span><span class="blip b2"></span>
  </div>
  <div class="hero-copy">
    <div class="hero-kicker">RECON &middot; ANALYZE &middot; HARDEN</div>
    <div class="hero-title">Outpost — Attack Surface Analyzer</div>
    <div class="hero-sub">Map your exposure before an attacker does. Turn raw scan data into a prioritized, scored security report.</div>
    <div class="hero-badges">
      <span class="hero-badge">7 risk categories</span>
      <span class="hero-badge">OWASP / CWE aligned</span>
      <span class="hero-badge">A&ndash;F scoring</span>
      <span class="hero-badge">passive &middot; single request</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("### 🛡️ About")
    st.markdown("**Outpost** analyzes scan data (Nmap output or a single authorized HTTP header check) and produces a ranked vulnerability report with an A–F security score.")
    st.markdown('<div class="ethics"><b>Authorized use only.</b> The live check makes one standard HTTP request — the same as opening a page in a browser. No port scanning, brute forcing, or exploitation is performed.</div>', unsafe_allow_html=True)
    st.markdown('<div class="small-note"><b>Detection categories</b><br>outdated software · exposed ports · unencrypted HTTP · missing security headers · weak TLS · information disclosure · OS fingerprinting</div>', unsafe_allow_html=True)

if "recon" not in st.session_state:
    st.session_state.recon = ""

col_in, col_out = st.columns([1, 1.4], gap="large")

with col_in:
    st.markdown('<div class="sec-head">Target console</div>', unsafe_allow_html=True)
    target = st.text_input("Target domain or IP", placeholder="e.g. example.com")
    do_live = st.toggle("Attempt live header check (standard HTTP GET only)", value=True)
    if st.button("Load sample scan data"):
        st.session_state.recon = SAMPLE
    recon = st.text_area("Reconnaissance data (paste Nmap output, curl -I headers, etc.)", key="recon", height=220)
    authorized = st.checkbox("I confirm I own this target or have explicit authorization to test it.")
    run = st.button("🔍  Run analysis", type="primary", disabled=not authorized, use_container_width=True)

with col_out:
    st.markdown('<div class="sec-head">Assessment report</div>', unsafe_allow_html=True)
    if run:
        combined = recon or ""
        live_info = None
        if do_live and target.strip():
            with st.spinner("Performing single authorized HTTP request…"):
                ok, status, final_url, text = live_check(target)
            combined += "\n" + text
            live_info = f"HTTP {status} from {final_url}" if ok else f"failed — {text}"
        if not combined.strip():
            st.info("Enter a target with live check on, or paste some reconnaissance data.")
        else:
            findings = analyze(combined)
            value, grade, counts = score_findings(findings)
            gcolor = {"A": "#0E9488", "B": "#0E9488", "C": "#B4870F", "D": "#C96A22", "F": "#C7384A"}[grade]
            g1, g2 = st.columns([1, 2])
            with g1:
                st.markdown(
                    f"<div class='small-note'>SECURITY SCORE</div>"
                    f"<div class='score-num' style='color:{gcolor}'>{value}<span style='font-size:18px;color:var(--faint)'>/100</span></div>"
                    f"<span class='grade-pill' style='background:{gcolor}1a;color:{gcolor}'>GRADE {grade}</span>",
                    unsafe_allow_html=True)
                st.progress(value / 100)
            with g2:
                cc = st.columns(5)
                for i, s in enumerate(SEV_ORDER):
                    cc[i].markdown(f"<div class='sevbox'><div class='n' style='color:{SEV_COLOR[s]}'>{counts[s]}</div><div class='l'>{s.capitalize()}</div></div>", unsafe_allow_html=True)
            if live_info:
                st.caption(f"🌐 Live check: {live_info}")
            st.divider()
            if not findings:
                st.success("No findings matched the current rule set. This target looks clean, or try fuller Nmap (-sC -sV) output for deeper coverage.")
            else:
                for f in findings:
                    color = SEV_COLOR[f["sev"]]
                    with st.expander(f"{f['sev'].upper()}  ·  {f['title']}"):
                        st.markdown(f"<span class='sev-badge' style='background:{color}22;color:{color}'>{f['sev']}</span> &nbsp;<code style='font-size:11px'>{f['meta']}</code>", unsafe_allow_html=True)
                        st.write("")
                        st.write(f["desc"])
                        if f.get("evidence"):
                            st.code(f["evidence"])
                        if f.get("cve"):
                            st.caption(f"📎 Reference: {f['cve']}")
                        st.markdown(f"**✅ Recommended fix:** {f['fix']}")
                st.write("")
                st.download_button("⬇️  Download report (.md)",
                    data=build_markdown(target or "(pasted data)", findings, value, grade, live_info),
                    file_name=f"outpost-report-{(target or 'target').replace('/', '_')}.md",
                    mime="text/markdown", use_container_width=True)
    else:
        st.info("Enter a target or paste reconnaissance data, confirm authorization, then run an analysis. Use **Load sample scan data** to preview a report.")

st.divider()
st.caption("Outpost is an educational prototype for authorized security testing. Not a substitute for a professional penetration test.")