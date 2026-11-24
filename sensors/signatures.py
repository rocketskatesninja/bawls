"""
Request signatures, shared by the decoy (decoy_sensor.py) and the real-site
log sensor (site_log_sensor.py), so both judge a request the same way.

classify() labels one request with the first matching signature, most severe
first. The exploit signatures are the ones that ban (the app's web_exploit
rule); the rest are recorded but never ban.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Collection

# Every signature an event can carry, worst first: what classify() returns,
# plus the two the decoy assigns itself (a flood summary, and a report from
# the opt-in /browser-check page). The console has the same list
# (App\Models\Event::SIGNATURES); tests/Feature/SignatureParityTest.php fails
# if the two drift apart.
SIGNATURES = ("cve_probe", "rce", "sqli", "traversal", "login", "dirbust", "scanner_ua", "flood",
              "browser_check", "benign")

# The signatures that carry an attack payload: they raise web_exploit alerts
# and bans (Event::EXPLOIT_SIGNATURES in the console; same test).
EXPLOIT_SIGNATURES = frozenset({"cve_probe", "rce", "sqli", "traversal"})

# Form fields, query parameters and headers whose values are credentials, by
# name. Their values are masked before an event is stored.
SECRET_FIELD_RE = re.compile(r"pass|pwd|secret|token|api[_-]?key|auth", re.IGNORECASE)

# Where credentials get POSTed: the fake login forms, plus the paths bots send
# credentials to directly (WordPress, phpMyAdmin, Joomla, Drupal, generic).
LOGIN_PATHS = {
    "/wp-login.php", "/admin", "/admin/", "/login",
    "/phpmyadmin/", "/phpmyadmin/index.php", "/pma/", "/pma/index.php",
    "/administrator/", "/administrator/index.php", "/user/login",
}

SCANNER_UA_RE = re.compile(
    r"nikto|sqlmap|nmap|masscan|zgrab|zmap|nuclei|gobuster|dirbuster|feroxbuster|"
    r"wpscan|curl|wget|python-requests|python-urllib|go-http-client|libwww|httpx|"
    r"censys|shodan|semrush|ahrefs|bitdiscovery|l9explore",
    re.IGNORECASE,
)

# Signature rules, most severe first. Each pattern is matched against the
# lowercased path + query + body.
CVE_PROBE = (
    "${jndi:", "{{7*7}}", "/actuator", "/struts", "/solr/", "/_ignition/execute-solution",
    "/boaform", "/hnap1", "/cgi-bin/luci", "/vendor/phpunit", "think\\app", "/cgi-bin/",
    "/geoserver", "/owa/auth", "/autodiscover/autodiscover.xml", "cf-command",
    "androxgh0st",   # botnet hunting Laravel debug mode to steal .env (0x[]=androxgh0st)
    "$1:__proto__",  # React Server Components / Next.js RCE payload (React2Shell, CVE-2025-55182)
)
# Paths only ever requested to find one vulnerable product, matched exactly
# (a trailing slash aside) so a real site's own pages can't trip them.
CVE_PATHS = frozenset({
    "/developmentserver/metadatauploader",   # SAP NetWeaver Visual Composer upload (CVE-2025-31324)
    "/remote/login",                         # Fortinet FortiGate SSL VPN
    "/debug/default/view",                   # Yii debug panel left on in production
    "/web/debug/default/view",               # ...and under Yii's default web/ folder
    "/mcp", "/api/mcp", "/sse",              # AI-agent (MCP) servers left open
})
RCE_MARKERS = (";wget", ";curl", "|sh", "|bash", "$(", "`", "/bin/sh", "chmod +x", "() {")
SQLI_MARKERS = (
    "' or '1'='1", "' or 1=1", " or 1=1", "union select", "union all select",
    "sleep(", "benchmark(", "information_schema", "' --", "'--", "' #", "waitfor delay",
)
TRAVERSAL_MARKERS = ("../", "..\\", "..%2f", "..%5c", "/etc/passwd", "%2e%2e", "c:\\windows")
DIRBUST_MARKERS = (
    "/.git", "/.env", "/.svn", "/.aws", "/.ssh", "/backup", "/wp-admin", "/wp-content",
    "/wp-includes", "/phpinfo", "/phpmyadmin", "/administrator", "/config", "/.htaccess",
    "/.well-known/security", ".sql", ".bak", ".old", ".zip", "/xmlrpc.php",
    # secrets and credentials left in the web root
    "/appsettings", "credentials.json", "credentials.yml", "secrets.json", "secrets.yml",
    "/.npmrc", "/.s3cfg", "/.boto", "/.dockercfg", "/docker-compose", "/.azure/",
    "/.config/", "/.vscode/", "/.ds_store", "/.bzr", "/.hg/", "/env.", "=.env",
    "/info.php", "pp=env", "/status?full", "/wp-config", "/.netrc", "/.pypirc", "/.travis.yml",
    "/parameters.yml", "/settings.py", "/storage/logs/",
    # AI coding-agent configs and API keys left in the web root
    "/.claude/", "/.cursor/", "/.llm/",
    # WordPress: REST API and user enumeration (no WordPress here to find)
    "/wp-json", "rest_route=", "/wp-sitemap", "/author-sitemap", "author=", "/graphql",
)


def is_login_attempt(method: str, path: str, login_paths: Collection[str] = ()) -> bool:
    """A POST to a login path: someone (or something) submitting credentials.

    login_paths adds the theme's own sign-in forms (theme.json "logins").
    """
    return method == "POST" and (path in LOGIN_PATHS or path in login_paths)


def is_cross_site(own_host: str, referer: str, user_agent: str, sec_fetch_site: str = "") -> bool:
    """
    True when a browser made this request on behalf of another site's page: a
    link someone clicked there, or an image or script that page embeds. Anyone
    can publish <img src="https://your-site/?q=../">, and every visitor to
    their page would then send an "exploit attempt" they know nothing about,
    so the console records and alerts on these but never bans for them.

    The browser's own word comes first (Sec-Fetch-Site, sent over HTTPS);
    otherwise a Referer from a different site. Both can be forged, which only
    spares a forger the ban, not the alert; and a client that doesn't even
    claim to be a browser, or names a scanning tool, never counts.

    own_host is the site the request was for (its Host header, or the name
    the site-log sensor knows it by). A subdomain is the same site.
    """
    if not user_agent.startswith("Mozilla/") or SCANNER_UA_RE.search(user_agent):
        return False
    stated = sec_fetch_site.strip().lower()
    if stated:
        return stated == "cross-site"
    try:
        other = (urllib.parse.urlsplit(referer).hostname or "").lower().removeprefix("www.")
    except ValueError:
        return False
    own = own_host.strip().lower()
    own = own[1:].split("]")[0] if own.startswith("[") else own.split(":")[0]   # drop a port
    own = own.removeprefix("www.")
    if not other or not own:
        return False
    return other != own and not other.endswith("." + own) and not own.endswith("." + other)


def classify(method: str, path: str, query: str, body: str, user_agent: str,
             site_pages: Collection[str] = (), login_paths: Collection[str] = ()) -> str:
    """Label one request. Returns the first matching signature, most severe first.

    Matches against both the raw and the percent-decoded request, so
    union%20select or %24%7Bjndi is caught the same as its decoded form. Form
    bodies are decoded too (a login carrying admin'+or+1=1--), except on the
    site's own pages (site_pages, the theme's): there a human's free-text
    message (a quote, a backtick) must never read as an exploit, because
    exploits get banned. The theme's sign-in forms (login_paths) are decoded
    like any login: a browser never submits them (the page's script stops
    it), so only bots post there.
    """
    request = f"{path}?{query}".lower()
    body = (body or "").lower()
    parts = [request, urllib.parse.unquote_plus(request), body]
    if path not in site_pages or path in login_paths:
        parts.append(urllib.parse.unquote_plus(body))
    haystack = "\n".join(parts)

    if any(marker in haystack for marker in CVE_PROBE) or (path.lower().rstrip("/") or "/") in CVE_PATHS:
        return "cve_probe"
    if any(marker in haystack for marker in RCE_MARKERS):
        return "rce"
    if any(marker in haystack for marker in SQLI_MARKERS):
        return "sqli"
    if any(marker in haystack for marker in TRAVERSAL_MARKERS):
        return "traversal"
    if is_login_attempt(method, path, login_paths):
        return "login"
    if any(marker in haystack for marker in DIRBUST_MARKERS):
        return "dirbust"
    if user_agent and SCANNER_UA_RE.search(user_agent):
        return "scanner_ua"
    return "benign"
