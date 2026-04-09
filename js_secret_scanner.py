#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         JS Secret Scanner + Secret Endpoint Checker         ║
║         Wayback Machine Edition — v2.0                      ║
╠══════════════════════════════════════════════════════════════╣
║  Modes:                                                      ║
║   --js       js_files.txt         JS files via Wayback      ║
║   --endpoints ALL_secret_endpoints.txt  Live endpoint probe  ║
║   (both flags together = run both and merge report)          ║
╚══════════════════════════════════════════════════════════════╝

Usage examples:
  python3 js_secret_scanner.py --js js_files.txt
  python3 js_secret_scanner.py --endpoints ALL_secret_endpoints.txt
  python3 js_secret_scanner.py --js js_files.txt --endpoints ALL_secret_endpoints.txt
  python3 js_secret_scanner.py --endpoints ALL_secret_endpoints.txt -t 10 -o report.html
"""

import re, sys, time, json, argparse, threading, socket
import urllib.request, urllib.error, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict

# ══════════════════════════════════════════════════════════════
#  SENSITIVE DATA PATTERNS  (shared by both modes)
# ══════════════════════════════════════════════════════════════
PATTERNS = {
    # ── Cloud API Keys ──────────────────────────────────────
    "AWS Access Key":        r'(?<![A-Z0-9])(AKIA|AIPA|ASIA|AGPA|AROA|AIDA|ANPA|ANVA)[A-Z0-9]{16}(?![A-Z0-9])',
    "AWS Secret Key":        r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']',
    "Google API Key":        r'AIza[0-9A-Za-z\-_]{35}',
    "Google OAuth Token":    r'ya29\.[0-9A-Za-z\-_]+',
    "Firebase URL":          r'https://[a-z0-9\-]+\.firebaseio\.com',
    "Firebase API Key":      r'(?i)firebase.{0,20}["\']([A-Za-z0-9\-_]{35,})["\']',
    "Azure Storage Key":     r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}',
    "Azure SAS Token":       r'sv=\d{4}-\d{2}-\d{2}&s[a-z]=.{10,}&sig=[A-Za-z0-9%+/=]{40,}',
    "GCP Service Account":   r'"type":\s*"service_account"',
    "Cloudinary URL":        r'cloudinary://[0-9]{9,}:[A-Za-z0-9_\-]+@[a-zA-Z0-9]+',
    # ── Source Control ──────────────────────────────────────
    "GitHub Token":          r'(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}',
    "GitHub Classic Token":  r'[gG][iI][tT][hH][uU][bB].{0,30}["\']([0-9a-zA-Z]{40})["\']',
    "Gitlab Token":          r'glpat-[A-Za-z0-9\-_]{20}',
    "NPM Token":             r'npm_[A-Za-z0-9]{36}',
    # ── Messaging / Comms ───────────────────────────────────
    "Slack Token":           r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9]{10,12}-[a-z0-9]{32}',
    "Slack Webhook":         r'https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}',
    "Twilio Account SID":    r'AC[a-fA-F0-9]{32}',
    "Twilio Auth Token":     r'(?i)twilio.{0,20}["\']([a-f0-9]{32})["\']',
    "SendGrid API Key":      r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',
    "Mailgun API Key":       r'key-[0-9a-zA-Z]{32}',
    "Mailchimp API Key":     r'[0-9a-f]{32}-us[0-9]{1,2}',
    "Telegram Bot Token":    r'[0-9]{8,10}:[A-Za-z0-9_\-]{35}',
    # ── Payment ─────────────────────────────────────────────
    "Stripe Live Key":       r'sk_live_[0-9a-zA-Z]{24,}',
    "Stripe Public Key":     r'pk_live_[0-9a-zA-Z]{24,}',
    "Stripe Test Key":       r'sk_test_[0-9a-zA-Z]{24,}',
    "Square Access Token":   r'sq0atp-[0-9A-Za-z\-_]{22}',
    "Square OAuth Secret":   r'sq0csp-[0-9A-Za-z\-_]{43}',
    "PayPal Client ID":      r'(?i)paypal.{0,30}client.{0,10}["\']([A-Za-z0-9]{60,})["\']',
    "Shopify Token":         r'shpat_[a-fA-F0-9]{32}',
    "Shopify Secret":        r'shpss_[a-fA-F0-9]{32}',
    "Credit Card Number":    r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
    # ── AI / ML ─────────────────────────────────────────────
    "OpenAI API Key":        r'sk-[A-Za-z0-9]{48}',
    "Anthropic API Key":     r'sk-ant-[A-Za-z0-9\-_]{93,}',
    "Hugging Face Token":    r'hf_[A-Za-z0-9]{39}',
    # ── Infra / DevOps ──────────────────────────────────────
    "Heroku API Key":        r'[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    "Algolia API Key":       r'(?i)algolia.{0,30}["\']([A-Za-z0-9]{32})["\']',
    "Mapbox Token":          r'pk\.[a-zA-Z0-9]{60}\.[a-zA-Z0-9]{22}',
    "Okta API Token":        r'(?i)okta.{0,30}["\']([0-9a-zA-Z_\-]{42})["\']',
    "Vault Token":           r's\.[A-Za-z0-9]{24}',
    # ── Private Keys & Certs ────────────────────────────────
    "RSA Private Key":       r'-----BEGIN RSA PRIVATE KEY-----',
    "DSA Private Key":       r'-----BEGIN DSA PRIVATE KEY-----',
    "EC Private Key":        r'-----BEGIN EC PRIVATE KEY-----',
    "PGP Private Key":       r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    "Generic Private Key":   r'-----BEGIN PRIVATE KEY-----',
    "SSH Private Key":       r'-----BEGIN OPENSSH PRIVATE KEY-----',
    # ── Passwords & Auth ────────────────────────────────────
    "Password in Code":      r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']',
    "Secret in Code":        r'(?i)(secret|secretkey|secret_key)\s*[=:]\s*["\'][^"\']{6,}["\']',
    "Auth Token in Code":    r'(?i)(auth.?token|authtoken)\s*[=:]\s*["\'][^"\']{8,}["\']',
    "API Key in Code":       r'(?i)(api.?key|apikey|access.?key)\s*[=:]\s*["\'][A-Za-z0-9\-_./+=]{10,}["\']',
    "Bearer Token":          r'[Bb]earer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+',
    "Basic Auth in URL":     r'https?://[^:@\s]{3,}:[^@\s]{3,}@[^/\s]+',
    "JWT Token":             r'eyJ[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_.+/=]{10,}',
    "Hardcoded Email+Pass":  r'(?i)email\s*[=:]\s*["\'][^"\']+@[^"\']+["\'].{0,80}(password|passwd)\s*[=:]\s*["\'][^"\']+["\']',
    "Social Security Number":r'\b\d{3}-\d{2}-\d{4}\b',
    # ── Database Connection Strings ─────────────────────────
    "MongoDB URI":           r'mongodb(\+srv)?://[^:]+:[^@]+@[^\s"\']+',
    "MySQL Connection":      r'mysql://[^:]+:[^@]+@[^\s"\']+',
    "PostgreSQL Connection": r'postgres(ql)?://[^:]+:[^@]+@[^\s"\']+',
    "Redis Connection":      r'redis://[^:]+:[^@]+@[^\s"\']+',
    "JDBC Connection":       r'jdbc:[a-z]+://[^\s"\']+password=[^&\s"\']+',
    "FTP Credentials":       r'ftp://[^:]+:[^@]+@[^\s"\']+',
    # ── Internal / Debug ────────────────────────────────────
    "Internal IP":           r'(?<!\d)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)',
    "Localhost Reference":   r'http://localhost(:\d+)?[/\w\-\.?=&%]*',
    "Debug/Dev Endpoint":    r'(?i)(staging|dev|internal|test|debug|admin)\.(api|backend|server)\.[a-z]{2,}',
    "S3 Bucket":             r'https?://[a-z0-9\-]+\.s3\.amazonaws\.com/[^\s"\']+',
    "GraphQL Introspection": r'__schema|__type|IntrospectionQuery',
    "Stack Trace":           r'(?i)(traceback|stack\s*trace|exception\s*in\s*thread|at\s+[\w\.]+\([\w\.]+:\d+\))',
    "Debug Mode Flag":       r'(?i)(debug\s*[=:]\s*true|APP_DEBUG\s*[=:]\s*true|DEBUG\s*[=:]\s*1)',
    "Env File Content":      r'(?i)^(DB_PASSWORD|SECRET_KEY|API_KEY|JWT_SECRET)\s*=\s*.+',
    "Version Disclosure":    r'(?i)(X-Powered-By|Server):\s*(PHP/[\d.]+|Apache/[\d.]+|nginx/[\d.]+)',
}

SEVERITY = {
    "CRITICAL": {
        "RSA Private Key","DSA Private Key","EC Private Key","PGP Private Key",
        "Generic Private Key","SSH Private Key","AWS Secret Key","Password in Code",
        "Secret in Code","MongoDB URI","MySQL Connection","PostgreSQL Connection",
        "Redis Connection","JDBC Connection","Stripe Live Key","Basic Auth in URL",
        "Hardcoded Email+Pass","Credit Card Number","Social Security Number",
        "GCP Service Account","Env File Content","Azure Storage Key","Azure SAS Token",
    },
    "HIGH": {
        "AWS Access Key","GitHub Token","GitHub Classic Token","Slack Token",
        "Slack Webhook","Stripe Test Key","SendGrid API Key","Firebase API Key",
        "Mailgun API Key","Heroku API Key","Shopify Token","Shopify Secret",
        "NPM Token","Gitlab Token","Telegram Bot Token","Hugging Face Token",
        "OpenAI API Key","Anthropic API Key","Okta API Token","JWT Token",
        "FTP Credentials","Auth Token in Code","API Key in Code","Bearer Token",
        "Vault Token","Stack Trace","Debug Mode Flag",
    },
    "MEDIUM": {
        "Google API Key","Google OAuth Token","Firebase URL","Mailchimp API Key",
        "Stripe Public Key","Twilio Account SID","Twilio Auth Token","Algolia API Key",
        "Square Access Token","Square OAuth Secret","PayPal Client ID","Cloudinary URL",
        "Mapbox Token","S3 Bucket","Debug/Dev Endpoint","GraphQL Introspection",
        "Version Disclosure",
    },
    "LOW": {
        "Internal IP","Localhost Reference","JDBC Connection","Social Security Number",
    },
}

def get_severity(name):
    for sev, names in SEVERITY.items():
        if name in names:
            return sev
    return "MEDIUM"

# ══════════════════════════════════════════════════════════════
#  SHARED HELPERS
# ══════════════════════════════════════════════════════════════
_COMPILED = {name: re.compile(pat, re.MULTILINE) for name, pat in PATTERNS.items()}

def scan_content(content, source_url):
    """Scan text content for all sensitive patterns. Returns list of finding dicts."""
    findings = []
    lines = content.splitlines()
    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        for name, regex in _COMPILED.items():
            for match in regex.finditer(line):
                val = match.group(0)
                display = (val[:8] + "…" + val[-4:]) if len(val) > 16 else (val[:6] + "***")
                findings.append({
                    "pattern":  name,
                    "severity": get_severity(name),
                    "line_no":  line_no,
                    "matched":  display,
                    "context":  stripped[:130],
                    "source":   source_url,
                })
    # deduplicate
    seen, out = set(), []
    for f in findings:
        k = (f["pattern"], f["line_no"], f["matched"])
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out

def redact(val):
    if len(val) > 16:
        return val[:8] + "…" + val[-4:]
    return val[:6] + "***"

# ══════════════════════════════════════════════════════════════
#  MODE 1 - JS FILES VIA WAYBACK MACHINE  (v3.0 - fixed CDX)
# ══════════════════════════════════════════════════════════════
# Bugs fixed vs v2.0:
#  BUG1: filter=statuscode:200 dropped captures stored with status '-' or '0'
#  BUG2: collapse=digest too aggressive - only 1 snapshot per digest kept
#  BUG3: limit=3 too low - missed snapshots that existed
#  BUG4: No retry on CDX 429/503/timeout - returned [] silently
#  BUG5: matchType not set - CDX used prefix match, missed exact URL
#  BUG6: 'if_' modifier injected Wayback toolbar JS into scanned content
#        Fix: use 'id_' (raw), fallback to 'if_' only if id_ fails
#  BUG7: Single CDX query = 1 failure point, no fallback strategy
#        Fix: 4-strategy cascade (strict->loose->raw->prefix)
#  BUG8: except Exception: return [] hid all CDX errors silently

# MODE1_REPLACEMENT
WAYBACK_CDX  = "https://web.archive.org/cdx/search/cdx"
WAYBACK_BASE = "https://web.archive.org/web"

CDX_DELAY   = 0.3   # was 1.0 — only needed between CDX strategies to avoid 429
FETCH_DELAY = 0.1   # was 0.5 — brief pause between snapshot fetches


def _req(url, timeout=20, retries=3):
    headers = {
        "User-Agent":      "Mozilla/5.0 (compatible; JSSecretScanner/3.0)",
        "Accept-Encoding": "identity",
        "Accept":          "*/*",
    }
    last_err = "unknown"
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            last_err = "HTTP %s" % e.code
            if e.code in (429, 503, 502):
                time.sleep(2 * (attempt + 1))   # was 3× — gentler back-off for rate limits
                continue
            raise
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            last_err = str(e)
            time.sleep(1 * (attempt + 1))       # was 2× — faster retry on transient errors
    raise IOError("Failed after %d retries: %s" % (retries, last_err))


def _cdx_query(url, extra=None):
    params = {
        "url":       url,
        "output":    "json",
        "fl":        "timestamp,statuscode",
        "limit":     "10",
        "matchType": "exact",
    }
    if extra:
        params.update(extra)
    cdx_url = WAYBACK_CDX + "?" + urllib.parse.urlencode(params)
    try:
        raw  = _req(cdx_url, timeout=20, retries=3)
        data = json.loads(raw)
        if not isinstance(data, list) or len(data) <= 1:
            return []
        return [(row[0], row[1]) for row in data[1:]]
    except Exception as e:
        return [("ERROR", str(e))]


def get_wayback_snapshots(url):
    msgs = []

    # Strategy 1: exact + HTTP 200 + monthly dedup (fastest, most reliable)
    rows = _cdx_query(url, {"filter": "statuscode:200", "collapse": "timestamp:8"})
    errs = [sc for ts, sc in rows if ts == "ERROR"]
    if errs:
        msgs.append("CDX S1 error: %s" % errs[0])
    ts1 = [ts for ts, sc in rows if ts != "ERROR"]
    if ts1:
        msgs.append("CDX strategy 1 (exact+200+collapse): %d snapshot(s)" % len(ts1))
        return ts1, msgs
    time.sleep(CDX_DELAY)  # 0.3s — just enough to avoid 429

    # Strategy 2: exact + any status + monthly dedup
    rows = _cdx_query(url, {"collapse": "timestamp:8"})
    errs = [sc for ts, sc in rows if ts == "ERROR"]
    if errs:
        msgs.append("CDX S2 error: %s" % errs[0])
    ts2 = [ts for ts, sc in rows if ts != "ERROR" and sc not in ("-", "0", "")]
    if ts2:
        msgs.append("CDX strategy 2 (exact+any status): %d snapshot(s)" % len(ts2))
        return ts2, msgs

    # Strategies 3 & 4: run concurrently to save time
    def _s3():
        return _cdx_query(url, {"limit": "5"})
    def _s4():
        return _cdx_query(url, {
            "matchType": "prefix",
            "filter":    "statuscode:200",
            "collapse":  "urlkey",
            "limit":     "5",
        })

    time.sleep(CDX_DELAY)
    with ThreadPoolExecutor(max_workers=2) as pool:
        f3, f4 = pool.submit(_s3), pool.submit(_s4)
        rows3 = f3.result()
        rows4 = f4.result()

    ts3 = [ts for ts, sc in rows3 if ts != "ERROR"]
    if ts3:
        msgs.append("CDX strategy 3 (exact+no filter): %d snapshot(s)" % len(ts3))
        return ts3, msgs

    ts4 = [ts for ts, sc in rows4 if ts != "ERROR"]
    if ts4:
        msgs.append("CDX strategy 4 (prefix): %d snapshot(s)" % len(ts4))
        return ts4, msgs

    msgs.append("All 4 CDX strategies returned 0 snapshots")
    return [], msgs


def fetch_wayback_content(original_url, timestamp):
    # id_ = raw content (no toolbar injection)  -- FIX: was if_ which injects Wayback JS
    # if_ = with toolbar                        -- fallback only
    wb_id = "%s/%sid_/%s" % (WAYBACK_BASE, timestamp, original_url)
    wb_if = "%s/%sif_/%s" % (WAYBACK_BASE, timestamp, original_url)

    for wb_url in (wb_id, wb_if):
        try:
            content = _req(wb_url, timeout=30, retries=2)
            if not content or len(content) < 10:
                continue
            c_start = content[:500].lower()
            if "<html" in c_start and "wayback machine" in c_start:
                continue
            return content, wb_url
        except Exception:
            continue
    return None, wb_id


def fetch_direct(url):
    try:
        return _req(url, timeout=15, retries=2)
    except Exception:
        return None


def process_js_url(url, results_store, lock, verbose=True):
    url = url.strip()
    if not url or url.startswith("#"):
        return

    entry = {
        "url":       url,
        "snapshots": [],
        "findings":  [],
        "errors":    [],
        "status":    "pending",
        "mode":      "js",
    }

    if verbose:
        print("  [JS] %s" % url)

    timestamps, cdx_msgs = get_wayback_snapshots(url)
    entry["errors"].extend(cdx_msgs)

    if not timestamps:
        entry["errors"].append("No snapshots - trying live fetch")
        content = fetch_direct(url)
        if content:
            entry["snapshots"].append({"timestamp": "live", "wb_url": url})
            entry["findings"] = scan_content(content, url)
            entry["status"]   = "scanned_direct"
        else:
            entry["status"] = "no_snapshot"
            entry["errors"].append("Live fetch also failed")
    else:
        # Limit to best 3 snapshots; fetch them concurrently
        ts_list = timestamps[:3]

        def _fetch_snap(ts):
            content, wb_url = fetch_wayback_content(url, ts)
            return ts, wb_url, content

        snap_results = []
        with ThreadPoolExecutor(max_workers=min(len(ts_list), 3)) as pool:
            futures = {pool.submit(_fetch_snap, ts): ts for ts in ts_list}
            for fut in as_completed(futures):
                try:
                    snap_results.append(fut.result())
                except Exception as e:
                    entry["errors"].append("Snapshot fetch error: %s" % e)

        # Process fetched snapshots; stop scanning once findings are found
        for ts, wb_url, content in snap_results:
            snap = {"timestamp": ts, "wb_url": wb_url}
            if content:
                new_findings          = scan_content(content, wb_url)
                snap["finding_count"] = len(new_findings)
                snap["bytes"]         = len(content)
                entry["findings"].extend(new_findings)
                entry["status"] = "scanned"
                # Early-exit: no need to scan more snapshots once secrets found
                if new_findings:
                    entry["snapshots"].append(snap)
                    break
            else:
                snap["finding_count"] = 0
                entry["errors"].append("Snapshot %s: id_ and if_ both failed" % ts)
            entry["snapshots"].append(snap)

        if entry["status"] == "pending":
            entry["status"] = "no_snapshot"

    seen, deduped = set(), []
    for f in entry["findings"]:
        k = (f["pattern"], f["matched"])
        if k not in seen:
            seen.add(k)
            deduped.append(f)
    entry["findings"] = deduped

    if verbose:
        cnt   = len(entry["findings"])
        snaps = len([s for s in entry["snapshots"]
                     if s.get("bytes", 0) > 0 or s.get("timestamp") == "live"])
        tag   = "!  %d findings" % cnt if cnt else "v  clean"
        strat = next((m for m in entry["errors"] if "strategy" in m.lower()), "")
        extra = "  [%s]" % strat if strat else ""
        print("      %s  [%s]  %d snapshot(s)%s" % (tag, entry["status"], snaps, extra))

    with lock:
        results_store.append(entry)

# ══════════════════════════════════════════════════════════════
#  MODE 2 — SECRET ENDPOINT CHECKER
# ══════════════════════════════════════════════════════════════

# HTTP methods to try per endpoint
HTTP_METHODS   = ["GET", "POST", "OPTIONS", "HEAD"]

# Extra headers that sometimes reveal secrets in responses
PROBE_HEADERS  = {
    "User-Agent":      "Mozilla/5.0 (compatible; SecretScanner/2.0)",
    "Accept":          "application/json, text/html, */*",
    "Accept-Language": "en-US,en;q=0.9",
}

# Response headers that often leak sensitive info
SENSITIVE_HEADERS = [
    "x-powered-by", "server", "x-aspnet-version", "x-aspnetmvc-version",
    "x-debug-token", "x-debug-token-link", "x-environment", "x-version",
    "x-api-version", "x-request-id", "x-correlation-id", "x-backend-server",
    "x-forwarded-for", "x-real-ip", "x-original-url", "x-rewrite-url",
    "access-control-allow-origin", "access-control-allow-credentials",
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options",
]

# Status codes that are particularly interesting
INTERESTING_STATUS = {
    200: "OK — content exposed",
    201: "Created — write access",
    204: "No Content",
    301: "Redirect",
    302: "Redirect",
    400: "Bad Request",
    401: "Unauthorized — endpoint exists",
    403: "Forbidden — endpoint exists",
    405: "Method Not Allowed — endpoint exists",
    500: "Internal Server Error — possible info leak",
    502: "Bad Gateway",
    503: "Service Unavailable",
}

def probe_endpoint(url, method="GET", timeout=10):
    """Probe a single endpoint. Returns (status, headers_dict, body, final_url, elapsed_ms, error)."""
    try:
        req = urllib.request.Request(url, method=method, headers=PROBE_HEADERS)
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = int((time.time() - t0) * 1000)
            body    = resp.read(1024 * 512).decode("utf-8", errors="replace")  # max 512 KB
            headers = dict(resp.headers)
            return resp.status, headers, body, resp.url, elapsed, None
    except urllib.error.HTTPError as e:
        elapsed = int((time.time() - t0) * 1000) if 't0' in dir() else 0
        try:
            body = e.read(65536).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, dict(e.headers), body, url, elapsed, None
    except urllib.error.URLError as e:
        return None, {}, "", url, 0, str(e.reason)
    except socket.timeout:
        return None, {}, "", url, timeout*1000, "Timeout"
    except Exception as e:
        return None, {}, "", url, 0, str(e)

def check_cors(headers):
    """Check for dangerous CORS config."""
    issues = []
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    if acao == "*":
        issues.append("Wildcard CORS (*)")
    if acao and acao != "*" and acac.lower() == "true":
        issues.append(f"CORS with credentials: {acao[:60]}")
    return issues

def check_security_headers(headers):
    """Return list of missing important security headers."""
    missing = []
    checks = {
        "strict-transport-security": "Missing HSTS",
        "content-security-policy":   "Missing CSP",
        "x-frame-options":           "Missing X-Frame-Options",
        "x-content-type-options":    "Missing X-Content-Type-Options",
    }
    for hdr, msg in checks.items():
        if hdr not in {k.lower() for k in headers}:
            missing.append(msg)
    return missing

def extract_interesting_headers(headers):
    """Pull out headers that may disclose sensitive info."""
    out = {}
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for h in SENSITIVE_HEADERS:
        if h in lower_headers:
            out[h] = lower_headers[h]
    return out

def process_endpoint(url, results_store, lock, methods=None, verbose=True):
    """Full pipeline for one endpoint: probe → scan body → analyse headers."""
    url = url.strip()
    if not url or url.startswith("#"):
        return

    if not url.startswith("http"):
        url = "https://" + url

    if verbose:
        print(f"  [EP] {url}")

    entry = {
        "url":      url,
        "mode":     "endpoint",
        "probes":   [],
        "findings": [],
        "errors":   [],
        "status":   "pending",
        "open":     False,
    }

    used_methods = methods or ["GET"]
    all_findings = []

    for method in used_methods:
        status, headers, body, final_url, elapsed, err = probe_endpoint(url, method=method)

        probe = {
            "method":      method,
            "status":      status,
            "elapsed_ms":  elapsed,
            "final_url":   final_url,
            "error":       err,
            "status_note": INTERESTING_STATUS.get(status, ""),
            "headers":     extract_interesting_headers(headers),
            "cors_issues": check_cors(headers),
            "sec_headers": check_security_headers(headers) if method == "GET" else [],
            "body_length": len(body),
            "findings":    [],
        }

        if status is not None:
            entry["open"] = True
            entry["status"] = f"HTTP {status}"

            # Scan response body for secrets
            if body:
                body_findings = scan_content(body, f"{url} [{method} response body]")
                probe["findings"] = body_findings
                all_findings.extend(body_findings)

            # Scan response header values for secrets
            for hname, hval in headers.items():
                hfindings = scan_content(hval, f"{url} [header: {hname}]")
                probe["findings"].extend(hfindings)
                all_findings.extend(hfindings)

            # Interesting status codes
            if status in (500, 502):
                probe["findings"].append({
                    "pattern":  "Server Error Disclosure",
                    "severity": "HIGH",
                    "line_no":  0,
                    "matched":  f"HTTP {status}",
                    "context":  body[:120] if body else "",
                    "source":   url,
                })
                all_findings.append(probe["findings"][-1])

            # CORS issues → treat as findings
            for ci in probe["cors_issues"]:
                f = {"pattern": "CORS Misconfiguration", "severity": "HIGH",
                     "line_no": 0, "matched": ci[:40], "context": ci, "source": url}
                probe["findings"].append(f)
                all_findings.append(f)

            # Verbose header leaks
            for hname in ["x-powered-by", "server", "x-aspnet-version", "x-debug-token", "x-environment"]:
                lh = {k.lower(): v for k, v in headers.items()}
                if hname in lh:
                    f = {"pattern": "Version/Server Disclosure", "severity": "LOW",
                         "line_no": 0, "matched": f"{hname}: {lh[hname][:40]}",
                         "context": f"Response header leaks technology: {hname}={lh[hname][:80]}",
                         "source": url}
                    probe["findings"].append(f)
                    all_findings.append(f)

        else:
            probe["error"] = err or "No response"

        entry["probes"].append(probe)
        time.sleep(0.2)

    # Deduplicate all findings
    seen, deduped = set(), []
    for f in all_findings:
        k = (f["pattern"], f["matched"])
        if k not in seen:
            seen.add(k)
            deduped.append(f)
    entry["findings"] = deduped

    if not entry["open"]:
        entry["status"] = "unreachable"

    if verbose:
        cnt = len(entry["findings"])
        stat_label = entry["status"]
        print(f"      {'⚠  ' + str(cnt) + ' findings' if cnt else '✓  clean'}  [{stat_label}]")

    with lock:
        results_store.append(entry)

# ══════════════════════════════════════════════════════════════
#  HTML REPORT  (unified — two tabs)
# ══════════════════════════════════════════════════════════════
SEV_COLOR = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#e6b800", "LOW": "#3498db"}
SEV_BG    = {"CRITICAL": "#fdecea", "HIGH": "#fef3e2", "MEDIUM": "#fffde7", "LOW": "#e8f4fd"}

def _sev_badge(sev):
    c = SEV_COLOR.get(sev, "#888")
    return f'<span style="background:{c};color:#fff;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700">{sev}</span>'

def _findings_table(findings):
    if not findings:
        return '<div style="padding:12px 16px;color:#27ae60;font-size:13px">✓ No sensitive data detected.</div>'
    rows = ""
    for f in findings:
        sc = SEV_COLOR.get(f["severity"], "#888")
        rows += f"""<tr style="border-bottom:1px solid #f0f0f0">
          <td style="padding:8px 10px">{_sev_badge(f['severity'])}</td>
          <td style="padding:8px 10px;font-size:13px">{f['pattern']}</td>
          <td style="padding:8px 10px;font-family:monospace;font-size:12px;color:{sc}">{f['matched']}</td>
          <td style="padding:8px 10px;text-align:center;font-size:12px">{f['line_no'] or '—'}</td>
          <td style="padding:8px 10px;font-size:11px;font-family:monospace;max-width:380px;word-break:break-all;color:#555">{f['context'][:110]}</td>
        </tr>"""
    return f"""<table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead><tr style="background:#dee2e6;font-size:12px">
        <th style="padding:8px 10px;text-align:left">Severity</th>
        <th style="padding:8px 10px;text-align:left">Pattern</th>
        <th style="padding:8px 10px;text-align:left">Match (redacted)</th>
        <th style="padding:8px 10px">Line</th>
        <th style="padding:8px 10px;text-align:left">Context</th>
      </tr></thead><tbody>{rows}</tbody></table>"""

def _js_rows(js_results):
    rows = ""
    for r in sorted(js_results, key=lambda x: -len(x["findings"])):
        uid       = id(r)
        url       = r["url"]
        snaps     = len(r["snapshots"])
        status    = r["status"]
        findings  = r["findings"]
        cnt       = len(findings)
        bc        = "#e74c3c" if cnt else "#27ae60"
        bl        = f"{cnt} finding(s)" if cnt else "Clean"
        snap_links = " | ".join(
            f'<a href="{s["wb_url"]}" target="_blank" style="color:#0066cc">{s["timestamp"]}</a>'
            for s in r["snapshots"]
        ) or "—"
        errors_html = f'<div style="padding:6px 12px;font-size:11px;color:#c0392b">⚠ {"; ".join(r["errors"])}</div>' if r["errors"] else ""
        rows += f"""
        <tr class="clickrow" onclick="tog('{uid}')" style="cursor:pointer;border-bottom:1px solid #e9ecef">
          <td style="padding:10px 12px;font-family:monospace;font-size:12px;word-break:break-all">{url}</td>
          <td style="padding:10px 12px;text-align:center">{snaps}</td>
          <td style="padding:10px 12px;font-size:12px">{snap_links}</td>
          <td style="padding:10px 12px;font-size:12px;color:#666">{status}</td>
          <td style="padding:10px 12px"><span style="background:{bc};color:#fff;padding:2px 8px;border-radius:12px;font-size:12px">{bl}</span></td>
        </tr>
        <tr id="d{uid}" style="display:none">
          <td colspan="5" style="padding:0;background:#f8f9fa">
            {_findings_table(findings)}{errors_html}
          </td>
        </tr>"""
    return rows

def _ep_rows(ep_results):
    rows = ""
    for r in sorted(ep_results, key=lambda x: -len(x["findings"])):
        uid      = id(r)
        url      = r["url"]
        status   = r["status"]
        findings = r["findings"]
        cnt      = len(findings)
        bc       = "#e74c3c" if cnt else ("#27ae60" if r["open"] else "#95a5a6")
        bl       = f"{cnt} finding(s)" if cnt else ("Clean" if r["open"] else "Unreachable")

        probe_rows = ""
        for p in r["probes"]:
            sc  = "#27ae60" if p["status"] and p["status"] < 400 else "#e74c3c"
            st  = f'<span style="color:{sc};font-weight:700">{p["status"] or "—"}</span>'
            crs = " | ".join(p.get("cors_issues", [])) or "—"
            sec = " | ".join(p.get("sec_headers", [])) or "OK"
            hdr_html = "".join(
                f'<div style="font-family:monospace;font-size:11px"><b>{k}</b>: {v[:80]}</div>'
                for k, v in (p.get("headers") or {}).items()
            ) or "<em>none</em>"
            probe_rows += f"""
            <tr style="border-bottom:1px solid #e0e0e0;vertical-align:top">
              <td style="padding:8px 10px;font-weight:700">{p['method']}</td>
              <td style="padding:8px 10px">{st} <span style="color:#666;font-size:11px">{p.get('status_note','')}</span></td>
              <td style="padding:8px 10px;font-size:11px">{p['elapsed_ms']} ms</td>
              <td style="padding:8px 10px;font-size:11px;color:#c0392b">{crs}</td>
              <td style="padding:8px 10px;font-size:11px;color:#7f8c8d">{sec}</td>
              <td style="padding:8px 10px">{hdr_html}</td>
            </tr>"""

        errors_html = f'<div style="padding:6px 12px;font-size:11px;color:#c0392b">⚠ {"; ".join(r["errors"])}</div>' if r["errors"] else ""

        rows += f"""
        <tr class="clickrow" onclick="tog('{uid}')" style="cursor:pointer;border-bottom:1px solid #e9ecef">
          <td style="padding:10px 12px;font-family:monospace;font-size:12px;word-break:break-all">{url}</td>
          <td style="padding:10px 12px;font-size:12px;color:#555">{status}</td>
          <td style="padding:10px 12px"><span style="background:{bc};color:#fff;padding:2px 8px;border-radius:12px;font-size:12px">{bl}</span></td>
        </tr>
        <tr id="d{uid}" style="display:none">
          <td colspan="3" style="padding:0;background:#f8f9fa">
            <div style="padding:8px 12px;font-size:12px;font-weight:600;color:#555;border-bottom:1px solid #dee2e6">HTTP Probe Results</div>
            <table style="width:100%;border-collapse:collapse;font-size:12px">
              <thead><tr style="background:#dee2e6">
                <th style="padding:7px 10px">Method</th><th style="padding:7px 10px">Status</th>
                <th style="padding:7px 10px">Latency</th><th style="padding:7px 10px">CORS</th>
                <th style="padding:7px 10px">Security Headers</th><th style="padding:7px 10px">Info Headers</th>
              </tr></thead><tbody>{probe_rows}</tbody>
            </table>
            <div style="padding:8px 12px;font-size:12px;font-weight:600;color:#555;border-bottom:1px solid #dee2e6;border-top:1px solid #dee2e6">Secret Findings in Response</div>
            {_findings_table(findings)}{errors_html}
          </td>
        </tr>"""
    return rows

def build_html_report(js_results, ep_results, output_path):
    all_results   = js_results + ep_results
    total_findings= sum(len(r["findings"]) for r in all_results)
    sev           = defaultdict(int)
    for r in all_results:
        for f in r["findings"]:
            sev[f["severity"]] += 1

    js_count = len(js_results)
    ep_count = len(ep_results)
    ep_open  = sum(1 for r in ep_results if r.get("open"))
    ep_vuln  = sum(1 for r in ep_results if r["findings"])
    js_vuln  = sum(1 for r in js_results if r["findings"])

    js_tab_html = ""
    if js_results:
        js_tab_html = f"""
        <div class="card">
          <div class="card-header">
            <span>📄 JS Files — Wayback Machine Scan</span>
            <span style="font-size:13px;font-weight:400">{js_count} files · {js_vuln} with findings</span>
          </div>
          <table style="width:100%;border-collapse:collapse">
            <thead><tr style="background:#e9ecef">
              <th style="padding:10px 12px;text-align:left">JS File URL</th>
              <th style="padding:10px 12px;text-align:center">Snapshots</th>
              <th style="padding:10px 12px;text-align:left">Wayback Links</th>
              <th style="padding:10px 12px">Status</th>
              <th style="padding:10px 12px">Result</th>
            </tr></thead>
            <tbody>{_js_rows(js_results)}</tbody>
          </table>
        </div>"""

    ep_tab_html = ""
    if ep_results:
        ep_tab_html = f"""
        <div class="card">
          <div class="card-header" style="background:#1a3a2a">
            <span>🔌 Secret Endpoints — Live Probe</span>
            <span style="font-size:13px;font-weight:400">{ep_count} endpoints · {ep_open} reachable · {ep_vuln} with findings</span>
          </div>
          <table style="width:100%;border-collapse:collapse">
            <thead><tr style="background:#e9ecef">
              <th style="padding:10px 12px;text-align:left">Endpoint URL</th>
              <th style="padding:10px 12px">HTTP Status</th>
              <th style="padding:10px 12px">Result</th>
            </tr></thead>
            <tbody>{_ep_rows(ep_results)}</tbody>
          </table>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secret Scanner Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f0f2f5;color:#222}}
  header{{background:linear-gradient(135deg,#0d1117,#1a1a2e,#16213e);color:#fff;padding:28px 40px;border-bottom:3px solid #e74c3c}}
  header h1{{font-size:24px;font-weight:800;margin-bottom:6px;letter-spacing:-.5px}}
  header p{{color:#8b949e;font-size:13px}}
  .container{{max-width:1400px;margin:24px auto;padding:0 20px}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:14px;margin-bottom:24px}}
  .stat{{background:#fff;border-radius:10px;padding:16px;text-align:center;box-shadow:0 1px 4px rgba(0,0,0,.07);border-top:3px solid #dee2e6}}
  .stat .val{{font-size:28px;font-weight:800;margin-bottom:2px}}
  .stat .lbl{{font-size:11px;color:#666;text-transform:uppercase;letter-spacing:.6px}}
  .card{{background:#fff;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.08);overflow:hidden;margin-bottom:28px}}
  .card-header{{padding:14px 20px;background:#1a1a2e;color:#fff;font-weight:700;font-size:14px;display:flex;justify-content:space-between;align-items:center}}
  .clickrow:hover{{background:#f1f3f5!important}}
  footer{{text-align:center;color:#999;font-size:12px;padding:24px;border-top:1px solid #e9ecef;margin-top:10px}}
  a{{color:#0066cc}}
</style>
</head>
<body>
<header>
  <h1>🔍 Secret Scanner — JS Files + Endpoints</h1>
  <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")} &nbsp;|&nbsp;
     {js_count} JS files &nbsp;·&nbsp; {ep_count} endpoints &nbsp;·&nbsp;
     {total_findings} total findings</p>
</header>
<div class="container">
  <div class="stats">
    <div class="stat" style="border-top-color:#e74c3c">
      <div class="val" style="color:#e74c3c">{total_findings}</div>
      <div class="lbl">Total Findings</div>
    </div>
    <div class="stat" style="border-top-color:#e74c3c">
      <div class="val" style="color:#e74c3c">{sev['CRITICAL']}</div>
      <div class="lbl">Critical</div>
    </div>
    <div class="stat" style="border-top-color:#e67e22">
      <div class="val" style="color:#e67e22">{sev['HIGH']}</div>
      <div class="lbl">High</div>
    </div>
    <div class="stat" style="border-top-color:#e6b800">
      <div class="val" style="color:#e6b800">{sev['MEDIUM']}</div>
      <div class="lbl">Medium</div>
    </div>
    <div class="stat" style="border-top-color:#3498db">
      <div class="val" style="color:#3498db">{sev['LOW']}</div>
      <div class="lbl">Low</div>
    </div>
    <div class="stat" style="border-top-color:#8e44ad">
      <div class="val" style="color:#8e44ad">{js_count}</div>
      <div class="lbl">JS Files</div>
    </div>
    <div class="stat" style="border-top-color:#27ae60">
      <div class="val" style="color:#27ae60">{ep_open}</div>
      <div class="lbl">Open Endpoints</div>
    </div>
    <div class="stat" style="border-top-color:#c0392b">
      <div class="val" style="color:#c0392b">{ep_vuln + js_vuln}</div>
      <div class="lbl">Vulnerable Targets</div>
    </div>
  </div>

  {js_tab_html}
  {ep_tab_html}
</div>
<footer>
  Secret Scanner v2.0 &nbsp;·&nbsp; JS Files via Wayback Machine &nbsp;·&nbsp;
  Live Endpoint Probing &nbsp;·&nbsp; For <strong>authorized</strong> security research only
</footer>
<script>
function tog(uid){{
  var el=document.getElementById('d'+uid);
  if(el) el.style.display=(el.style.display==='none'||el.style.display==='')?'table-row':'none';
}}
// Init all detail rows hidden
document.querySelectorAll('[id^="d"]').forEach(function(el){{el.style.display='none';}});
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

def build_json_report(js_results, ep_results, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({"js_results": js_results, "endpoint_results": ep_results}, f, indent=2)

# ══════════════════════════════════════════════════════════════
#  THREADED RUNNER
# ══════════════════════════════════════════════════════════════

def run_threaded(items, worker_fn, worker_kwargs, threads):
    """Run worker_fn over items with a real thread-pool (no per-spawn sleep)."""
    results, lock = [], threading.Lock()
    def _wrap(item):
        worker_fn(item, results, lock, **worker_kwargs)
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(_wrap, item) for item in items]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception:
                pass
    return results

# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="Secret Scanner v2 — JS files (Wayback) + Secret Endpoint live probe",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan JS files only
  python3 js_secret_scanner.py --js js_files.txt

  # Scan secret endpoints only
  python3 js_secret_scanner.py --endpoints ALL_secret_endpoints.txt

  # Scan both (combined report)
  python3 js_secret_scanner.py --js js_files.txt --endpoints ALL_secret_endpoints.txt

  # Probe with multiple HTTP methods, more threads
  python3 js_secret_scanner.py --endpoints ALL_secret_endpoints.txt --methods GET POST OPTIONS -t 10
        """
    )
    parser.add_argument("--js",        metavar="FILE", help="JS URL list file (Wayback scan)")
    parser.add_argument("--endpoints", metavar="FILE", help="Secret endpoint list file (live probe)")
    parser.add_argument("-o","--output",  default="scan_report.html", help="HTML report output (default: scan_report.html)")
    parser.add_argument("-j","--json",    default="scan_report.json", help="JSON report output (default: scan_report.json)")
    parser.add_argument("-t","--threads", type=int, default=5, help="Concurrent threads (default: 5)")
    parser.add_argument("--methods",  nargs="+", default=["GET"],
                        choices=["GET","POST","OPTIONS","HEAD","PUT","DELETE","PATCH"],
                        help="HTTP methods for endpoint probing (default: GET)")
    parser.add_argument("-q","--quiet", action="store_true", help="Suppress per-item progress output")
    args = parser.parse_args()

    if not args.js and not args.endpoints:
        parser.print_help()
        print("\n[ERROR] Provide at least one of --js or --endpoints\n")
        sys.exit(1)

    print(f"\n{'═'*62}")
    print(f"  Secret Scanner v2.0 — JS Files + Endpoint Checker")
    print(f"{'═'*62}")
    print(f"  Patterns  : {len(PATTERNS)}")
    print(f"  Threads   : {args.threads}")
    print(f"  Methods   : {', '.join(args.methods)}")
    print(f"{'═'*62}")

    js_results = []
    ep_results = []

    # ── JS mode ──────────────────────────────────────────────
    if args.js:
        try:
            with open(args.js, encoding="utf-8") as f:
                js_urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            print(f"[ERROR] JS file list '{args.js}' not found.")
            sys.exit(1)
        print(f"\n[JS] Scanning {len(js_urls)} JS files via Wayback Machine …\n")
        js_results = run_threaded(
            js_urls, process_js_url,
            {"verbose": not args.quiet}, args.threads
        )

    # ── Endpoint mode ─────────────────────────────────────────
    if args.endpoints:
        try:
            with open(args.endpoints, encoding="utf-8") as f:
                ep_urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            print(f"[ERROR] Endpoint file '{args.endpoints}' not found.")
            sys.exit(1)
        print(f"\n[EP] Probing {len(ep_urls)} endpoints ({', '.join(args.methods)}) …\n")
        ep_results = run_threaded(
            ep_urls, process_endpoint,
            {"methods": args.methods, "verbose": not args.quiet}, args.threads
        )

    # ── Reports ───────────────────────────────────────────────
    build_html_report(js_results, ep_results, args.output)
    build_json_report(js_results, ep_results, args.json)

    # ── Summary ───────────────────────────────────────────────
    all_res = js_results + ep_results
    total   = sum(len(r["findings"]) for r in all_res)
    sev     = defaultdict(int)
    for r in all_res:
        for f in r["findings"]:
            sev[f["severity"]] += 1

    print(f"\n{'═'*62}")
    print(f"  SCAN COMPLETE")
    print(f"{'═'*62}")
    if js_results:
        js_vuln = sum(1 for r in js_results if r["findings"])
        print(f"  JS files   : {len(js_results)} scanned, {js_vuln} with findings")
    if ep_results:
        ep_open = sum(1 for r in ep_results if r.get("open"))
        ep_vuln = sum(1 for r in ep_results if r["findings"])
        print(f"  Endpoints  : {len(ep_results)} probed, {ep_open} reachable, {ep_vuln} with findings")
    print(f"  ─────────────────────────────────────")
    print(f"  CRITICAL   : {sev['CRITICAL']}")
    print(f"  HIGH       : {sev['HIGH']}")
    print(f"  MEDIUM     : {sev['MEDIUM']}")
    print(f"  LOW        : {sev['LOW']}")
    print(f"  TOTAL      : {total} findings")
    print(f"  ─────────────────────────────────────")
    print(f"  HTML  → {args.output}")
    print(f"  JSON  → {args.json}")
    print(f"{'═'*62}\n")

if __name__ == "__main__":
    main()
