#!/usr/bin/env python3
"""
Bawls decoy sensor.

A low-interaction HTTP honeypot. It serves the static "Bawls Inc." decoy site
(and plausible bait pages at the paths scanners probe), records everything a
client sends, classifies the request, and ships it to the Bawls ingest API as a
`honeypot_http` event over the same batch/flush path the UFW sensor uses.

Low interaction by design: every response is static bytes read from the decoy
site or a built-in fallback. Nothing a client sends is executed, proxied, or
reflected. Request bodies are read up to a cap, and secret-looking form fields
are stored only if they appear in a bundled common-password list; anything else
is masked to its length and a keyed fingerprint (so repeats can be counted).
The same masking covers the body, the query string and secret headers.

Config (environment):
    TRIPWIRE_URL         ingest base URL      (default http://127.0.0.1:9119)
    TRIPWIRE_TOKEN       sensor ingest token  (required)
    DECOY_LISTEN         host:port to bind    (default 127.0.0.1:8088)
    DECOY_THEME_DIR      decoy site theme     (default <this dir>/themes/bawls-inc)
    DECOY_PASSWORDS      common-password list (default <this dir>/common_passwords.txt)
    DECOY_TRUSTED_PROXY  peer allowed to set X-Forwarded-For (default 127.0.0.1)
    DECOY_FLAKE_RATE     chance a flaky page 503s, 0..1       (default 0)
    DECOY_MAX_PER_MIN    stored events per source IP / minute (default 120)
    DECOY_BROWSER_CHECK_FLAG  flag file enabling /browser-check (default storage/app/decoy/…)

Usage:
    decoy_sensor.py            serve until stopped (SIGTERM flushes the batch)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import random
import re
import signal
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from outbox import Outbox, RateCap, env_int, is_ip, make_event
from signatures import SECRET_FIELD_RE, classify, is_cross_site, is_login_attempt

FLUSH_SECONDS = 5.0       # ship partial batches at least this often
BODY_READ_CAP = 16384     # bytes read from a request body, hard stop
BODY_EXCERPT_CAP = 4096   # chars of (masked) body kept in the event
HEADER_VALUE_CAP = 512    # chars kept per header value
HEADER_NAME_CAP = 64      # chars kept per header name
HEADERS_TOTAL_CAP = 8192  # chars of header names + values kept per request
MAX_HEADERS = 40          # headers kept per request
FAKE_SERVER = "Apache/2.4.41 (Ubuntu)"   # a plausible banner for the decoy

# Served content types by file extension; anything else is HTML.
CONTENT_TYPES = {
    ".txt": "text/plain; charset=utf-8",
    ".xml": "application/xml; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
}

# Real static assets (css/js/images/fonts) under the site dir are served as-is
# and NOT recorded — a browser pulls many per page view and they are just noise.
ASSET_EXTS = set(CONTENT_TYPES) - {".txt", ".xml", ".json"}

# A theme links its assets with a version query (/assets/site.css?v=<hash>), so
# a versioned URL never changes and browsers may keep it for a year without
# asking again, even on reload (Firefox re-checks on reload unless "immutable").
# That is what stops a refresh from showing the page before its stylesheet.
VERSIONED_ASSET_CACHE = "public, max-age=31536000, immutable"


def asset_cache_control(query: str) -> str | None:
    """Cache-Control for a static asset: long-lived only when the URL is versioned."""
    return VERSIONED_ASSET_CACHE if query else None


HOST_RE = re.compile(r"[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?")


def fill_origin(payload: bytes, host: str, fallback: str) -> bytes:
    """A theme's robots.txt and sitemap.xml say {{origin}} where a real site
    names itself. It becomes https:// plus the host the visitor asked for, so
    a theme never carries one install's domain to another. A Host header that
    isn't a plain hostname gets the server's address instead."""
    if b"{{origin}}" not in payload:
        return payload
    host = host.strip()
    if not HOST_RE.fullmatch(host):
        host = f"[{fallback}]" if ":" in fallback else fallback
    return payload.replace(b"{{origin}}", f"https://{host}".encode())


# Bait that looks like a live secret is assembled only when served, so the
# repository never holds a secret-shaped string (GitHub's push protection,
# and every key-scraper, would take the fake for a real leak). It's a dud.
BAIT_TOKENS = {
    b"{{fake_stripe_key}}": ("sk" + "_live_" + "bawlsEXAMPLEnotreal000000").encode(),
}


def fill_bait(payload: bytes) -> bytes:
    for token, value in BAIT_TOKENS.items():
        payload = payload.replace(token, value)
    return payload


def content_type_for(filename: str) -> str:
    return CONTENT_TYPES.get(Path(filename).suffix.lower(), "text/html; charset=utf-8")


SENSOR_DIR = Path(__file__).parent
DEFAULT_THEME_DIR = SENSOR_DIR / "themes" / "bawls-inc"
BAIT_DIR = SENSOR_DIR / "bait"   # theme-independent: bait pages keep one look whatever the decoy site's theme


@dataclass(frozen=True)
class Theme:
    """
    A decoy site: a folder of static pages plus theme.json, which maps clean
    request paths to files, names the pages that sometimes 503, and the
    not-found / unavailable pages. Optional "logins" maps the path a theme's
    sign-in form posts to -> the page a POST there gets (a failed sign-in);
    those POSTs are login attempts. Bait lives in BAIT_DIR, not in the theme.
    """
    root: Path
    name: str
    pages: dict[str, str]
    flaky: frozenset[str]
    not_found: str
    unavailable: str
    logins: dict[str, str] = field(default_factory=dict)


def load_theme(root: Path) -> Theme:
    """Read and validate a theme. Raises ValueError if it is incomplete or a file escapes it."""
    root = Path(root).resolve()
    data = json.loads((root / "theme.json").read_text(encoding="utf-8"))
    theme = Theme(
        root=root,
        name=str(data.get("name", root.name)),
        pages={str(k): str(v) for k, v in dict(data["pages"]).items()},
        flaky=frozenset(data.get("flaky", [])),
        not_found=str(data["not_found"]),
        unavailable=str(data["unavailable"]),
        logins={str(k): str(v) for k, v in dict(data.get("logins", {})).items()},
    )
    for filename in [*theme.pages.values(), *theme.logins.values(), theme.not_found, theme.unavailable]:
        candidate = (root / filename).resolve()
        if root not in candidate.parents or not candidate.is_file():
            raise ValueError(f"theme {theme.name!r}: missing or outside the theme: {filename}")
    if (set(theme.pages) | set(theme.logins)) & set(BAIT_PAGES):
        raise ValueError(f"theme {theme.name!r}: pages collide with bait paths")
    return theme


# Bait: paths scanners probe. Never linked from the site. (path -> file, status).
BAIT_PAGES = {
    "/wp-login.php": ("wp-login.html", 200),
    "/wp-admin": ("wp-login.html", 200),
    "/wp-admin/": ("wp-login.html", 200),
    "/xmlrpc.php": ("xmlrpc.txt", 200),
    "/phpmyadmin/": ("phpmyadmin.html", 200),
    "/phpmyadmin": ("phpmyadmin.html", 200),
    "/phpmyadmin/index.php": ("phpmyadmin.html", 200),
    "/pma/": ("phpmyadmin.html", 200),
    "/pma/index.php": ("phpmyadmin.html", 200),
    "/administrator/": ("admin-login.html", 200),
    "/administrator/index.php": ("admin-login.html", 200),
    "/user/login": ("admin-login.html", 200),
    "/admin": ("admin-login.html", 200),
    "/admin/": ("admin-login.html", 200),
    "/login": ("admin-login.html", 200),
    "/.env": ("dotenv.txt", 200),
    "/.git/config": ("gitconfig.txt", 200),
    "/.git/HEAD": ("git-head.txt", 200),
    "/wp-config.php.bak": ("wp-config-bak.txt", 200),
    "/wp-config.php~": ("wp-config-bak.txt", 200),
    "/.aws/credentials": ("aws-credentials.txt", 200),
    "/.ssh/id_rsa": ("id-rsa.txt", 200),
    "/.vscode/sftp.json": ("vscode-sftp.json", 200),
    "/config.json": ("config-json.json", 200),
    "/actuator/env": ("actuator-env.json", 200),
    "/actuator/health": ("actuator-health.json", 200),
    "/phpinfo.php": ("phpinfo.html", 200),
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php": ("eval-stdin.txt", 200),
    "/server-status": ("server-status.html", 200),
}

def client_ip(peer_ip: str, forwarded_for: str | None, trusted_proxy: str) -> str:
    """
    The source IP to record.

    Only honours X-Forwarded-For when the socket peer is the trusted reverse
    proxy, and then takes the right-most valid address — the one the proxy
    itself appended — so a client-forged left-hand value cannot win.
    """
    if peer_ip == trusted_proxy and forwarded_for:
        for candidate in reversed([part.strip() for part in forwarded_for.split(",")]):
            if is_ip(candidate):
                return candidate
    return peer_ip


def http_fingerprint(method: str, http_version: str, header_names: list[str],
                     accept: str, accept_encoding: str, accept_language: str) -> str:
    """
    A stable passive fingerprint of the request's *shape*.

    Built from the method, HTTP version, the order of the header names, and the
    Accept profile — all of which differ between real browsers and tools (curl,
    sqlmap, nikto, Go clients) regardless of the User-Agent they claim. No
    JavaScript and nothing the client didn't send on its own.
    """
    basis = "|".join([
        method,
        http_version,
        ",".join(name.lower() for name in header_names),
        accept or "",
        accept_encoding or "",
        accept_language or "",
    ])
    return hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:16]


def resolve_route(path: str, theme: Theme, method: str = "GET") -> tuple[int, str, str]:
    """
    Map a request to (status, filename, kind) without touching the disk.
    kind is one of: page (theme file), bait (BAIT_DIR file), error (theme
    file). An unknown path gets the theme's 404, the way a real site answers.
    A POST to one of the theme's sign-in paths gets its failed-sign-in page.
    """
    if method == "POST" and path in theme.logins:
        return (200, theme.logins[path], "page")
    if path in theme.pages:
        return (200, theme.pages[path], "page")
    if path in BAIT_PAGES:
        filename, status = BAIT_PAGES[path]
        return (status, filename, "bait")
    return (404, theme.not_found, "error")


def parse_form(body: bytes, content_type: str) -> dict[str, str]:
    """Best-effort form parse of a urlencoded body. Never raises."""
    if "application/x-www-form-urlencoded" not in (content_type or "").lower():
        return {}
    try:
        parsed = urllib.parse.parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
        return {key: values[0] for key, values in parsed.items()}
    except Exception:
        return {}


def password_key(token: str) -> bytes:
    """
    The key for password fingerprints, derived from the decoy's own secret
    token. The console keeps only a hash of that token, so its database alone
    can't test a fingerprint against a wordlist.
    """
    return hashlib.sha256(b"bawls password fingerprint\0" + token.encode()).digest()


def password_fingerprint(value: str, key: bytes) -> str:
    """A short keyed one-way hash: the same password gives the same 12 characters."""
    return hmac.new(key, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:12]


def mask_value(field: str, value: str, common_passwords: set[str], key: bytes = b"") -> str:
    """
    Keep ordinary field values (capped). For secret-looking fields, keep the
    value only if it is a known common password — the part worth studying — and
    otherwise reduce it to its length and a keyed fingerprint, so real secrets
    are never stored but a password tried again can still be counted.
    """
    if SECRET_FIELD_RE.search(field):
        if value in common_passwords:
            return value
        return f"[masked:{len(value)} chars #{password_fingerprint(value, key)}]"
    return value[:HEADER_VALUE_CAP]


def mask_form(form: dict[str, str], common_passwords: set[str], key: bytes = b"") -> dict[str, str]:
    return {name: mask_value(name, value, common_passwords, key) for name, value in form.items()}


def mask_query(query: str, common_passwords: set[str], key: bytes = b"") -> str:
    """
    A query string with its secret-looking parameters masked like form fields
    (?user=bob&password=...). One with no such parameter comes back exactly as
    sent, so probes read the way the client wrote them.
    """
    try:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    except ValueError:
        return query
    if not any(SECRET_FIELD_RE.search(name) for name, _ in pairs):
        return query
    return urllib.parse.urlencode([(name, mask_value(name, value, common_passwords, key)) for name, value in pairs])


def mask_body(body_text: str, form: dict[str, str]) -> str:
    """
    The body as kept in the event. A parsed form is rebuilt from its masked
    fields, so a typed password can't survive here after being masked there;
    any other body that names a secret is reduced to its length.
    """
    if form:
        return urllib.parse.urlencode(form)[:BODY_EXCERPT_CAP]
    if SECRET_FIELD_RE.search(body_text):
        return f"[masked:{len(body_text)} chars]"
    return body_text[:BODY_EXCERPT_CAP]


def mask_url(url: str, common_passwords: set[str], key: bytes) -> str:
    """A URL with any secret parameters in its query masked (see mask_query)."""
    base, mark, query = url.partition("?")
    return base + mark + mask_query(query, common_passwords, key)


def mask_header(name: str, value: str, common_passwords: set[str], key: bytes) -> str:
    """
    A header value as kept in the event. Credentials never are: Authorization
    keeps its scheme, Cookie keeps its cookie names, Referer has its secret
    query parameters masked, and any other secret-looking header (X-Api-Key,
    X-Auth-Token) keeps only its length.
    """
    lower = name.lower()
    if lower == "referer":
        return mask_url(value, common_passwords, key)[:HEADER_VALUE_CAP]
    if lower in ("authorization", "proxy-authorization"):
        scheme, _, credentials = value.strip().partition(" ")
        return f"{scheme[:32]} [masked:{len(credentials)} chars]" if credentials else f"[masked:{len(value)} chars]"
    if lower == "cookie":
        names = [part.split("=", 1)[0].strip()[:HEADER_NAME_CAP] for part in value.split(";") if part.strip()]
        return "; ".join(f"{cookie}=[masked]" for cookie in names)[:HEADER_VALUE_CAP]
    if SECRET_FIELD_RE.search(name):
        return f"[masked:{len(value)} chars]"
    return value[:HEADER_VALUE_CAP]


def kept_headers(items: list[tuple[str, str]], common_passwords: set[str], key: bytes) -> list[tuple[str, str]]:
    """
    The request's headers as kept in the event: at most MAX_HEADERS, names and
    values capped and credentials masked, and no more than HEADERS_TOTAL_CAP
    characters in all, so a client can't size the event.
    """
    kept, total = [], 0
    for name, value in items[:MAX_HEADERS]:
        name, value = name[:HEADER_NAME_CAP], mask_header(name, value, common_passwords, key)
        total += len(name) + len(value)
        if total > HEADERS_TOTAL_CAP:
            break
        kept.append((name, value))
    return kept


def clean_signal(value: object) -> object:
    """
    One browser-check signal, reduced to what the console shows: short text,
    a finite number, a yes/no, or a short list of short texts. Anything else
    (nested objects, NaN, broken Unicode) becomes None, so a crafted report
    can't produce an event the server refuses.
    """
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value if math.isfinite(value) and abs(value) < 1e15 else None
    if isinstance(value, str):
        return value.encode("utf-8", "replace").decode()[:200]
    if isinstance(value, list):
        return [item.encode("utf-8", "replace").decode()[:100] for item in value[:20] if isinstance(item, str)]
    return None


# --------------------------------------------------------------------------
# Server (thin; all the decisions live in the pure functions above)
# --------------------------------------------------------------------------

class _State:
    """Shared config, the flood counters and the outbox of pending events."""

    def __init__(self) -> None:
        self.token = os.environ.get("TRIPWIRE_TOKEN", "")
        self.password_key = password_key(self.token)
        # None without a token: main() refuses to start, and tests give it their own.
        self.outbox = Outbox.from_env()
        self.theme = load_theme(Path(os.environ.get("DECOY_THEME_DIR") or DEFAULT_THEME_DIR))
        self.trusted_proxy = os.environ.get("DECOY_TRUSTED_PROXY", "127.0.0.1")
        self.flake_rate = float(os.environ.get("DECOY_FLAKE_RATE", "0") or "0")
        self.common_passwords = _load_passwords(
            Path(os.environ.get("DECOY_PASSWORDS", SENSOR_DIR / "common_passwords.txt"))
        )
        # The disclosed browser-fingerprint test at /browser-check is served only
        # while this flag file exists; the admin toggles it (bawls:browser-check).
        self.browser_check_flag = Path(os.environ.get(
            "DECOY_BROWSER_CHECK_FLAG", SENSOR_DIR.parent / "storage/app/decoy/browser_check.enabled"))
        # Flood cap: at most this many stored events per source IP per minute, so
        # one scanner can't balloon the database. Overflow is counted, not stored,
        # and summarised as a single "(suppressed flood)" event per flush.
        self.cap = RateCap(env_int("DECOY_MAX_PER_MIN", 120))
        self.local_ip = "127.0.0.1"
        self.local_port = 0
        # Request threads only queue events; one sender thread does the
        # network I/O, so a slow or down ingest never holds up a response.
        self.wake = threading.Event()

    def browser_check_enabled(self) -> bool:
        try:
            return self.browser_check_flag.exists()
        except OSError:
            return False

    def should_ship(self, ip: str) -> bool:
        """True while the source is under its per-minute cap (DECOY_MAX_PER_MIN)."""
        return self.cap.allow(ip)

    def drain_suppressed(self) -> list[dict]:
        """One summary event per source the cap turned requests away from, so a
        flood is still on record: how big it was, without a row per request."""
        return [
            make_event(
                "honeypot_http", source, self.local_ip, dst_port=self.local_port,
                raw={"method": "-", "path": "(suppressed flood)", "signature": "flood",
                     "decoy": "flood", "suppressed": suppressed, "status": 0},
            )
            for source, suppressed in self.cap.drain()
        ]

    def add(self, event: dict) -> None:
        if self.outbox.add(event):
            self.wake.set()

    def flush(self) -> None:
        self.outbox.flush(self.drain_suppressed())


def _load_passwords(path: Path) -> set[str]:
    """The common-password list: one a line, blank lines and # comments skipped."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return set()
    return {line.strip() for line in lines if line.strip() and not line.startswith("#")}


class DecoyHandler(BaseHTTPRequestHandler):
    server_version = FAKE_SERVER
    sys_version = ""
    protocol_version = "HTTP/1.1"
    # A client that stalls mid-request is dropped after this many seconds, so
    # slow connections can't pin the decoy's small thread budget (TasksMax).
    timeout = 10
    state: _State  # injected on the server

    def log_message(self, *args: object) -> None:
        """Silence stdout logging; events go to the ingest API instead."""

    def handle_one(self, send_body: bool) -> None:
        """Answer one request, whatever its verb (see PROBE_VERBS), and record it."""
        try:
            parsed = urllib.parse.urlsplit(self.path)
            path, query = parsed.path or "/", parsed.query
            if self.command == "CONNECT":
                # "CONNECT example.com:443": the target is the whole point.
                path, query = self.path, ""

            length = self.headers.get("Content-Length", "")
            length = int(length) if length.isdigit() else 0
            raw_body = self.rfile.read(min(length, BODY_READ_CAP)) if length else b""

            # The disclosed, opt-in browser-fingerprint test — only when toggled
            # on. When off, /browser-check falls through to normal handling (an
            # unknown path), so it leaves no trace that the feature exists.
            if path.rstrip("/") == "/browser-check" and self.state.browser_check_enabled():
                self._browser_check(send_body, raw_body, path, query)
                return

            theme = self.state.theme
            status, filename, kind = resolve_route(path, theme, self.command)

            # A real static asset (css/js/image/font) that would otherwise 404 is
            # served as-is and not recorded — ordinary page-load noise.
            if kind == "error":
                asset = self._static_asset(path)
                if asset is not None:
                    body = self._read_file(theme.root, asset, 200)
                    self._respond(200, content_type_for(asset), body if send_body else b"",
                                  cache_control=asset_cache_control(query))
                    return

            if path in theme.flaky and random.random() < self.state.flake_rate:
                status, filename, kind = 503, theme.unavailable, "error"

            content_type = content_type_for(filename)
            payload = self._read_file(BAIT_DIR if kind == "bait" else theme.root, filename, status)
            if kind == "bait":
                payload = fill_bait(payload)
            if kind == "page" and filename.endswith((".txt", ".xml")):
                payload = fill_origin(payload, self.headers.get("Host", ""), self.connection.getsockname()[0])

            self._respond(status, content_type, payload if send_body else b"")
            self._record(path, query, raw_body, status, filename)
        except Exception as error:  # never let a prober crash the handler
            try:
                self._respond(500, "text/html; charset=utf-8", b"<h1>500</h1>")
            except Exception:
                pass
            print(f"handler error: {error}", file=sys.stderr)

    def do_GET(self) -> None:
        self.handle_one(send_body=True)

    def do_HEAD(self) -> None:
        self.handle_one(send_body=False)

    def do_POST(self) -> None:
        self.handle_one(send_body=True)

    def _browser_check(self, send_body: bool, raw_body: bytes, path: str, query: str) -> None:
        """Serve the disclosed fingerprint test (GET) or accept its result (POST)."""
        if self.command == "POST":
            fingerprint, summary = "", {}
            try:
                payload = json.loads(raw_body.decode("utf-8", "replace") or "{}")
                fingerprint = str(clean_signal(str(payload.get("fingerprint", ""))))[:64]
                signals = payload.get("signals") if isinstance(payload.get("signals"), dict) else {}
                keep = ("ua", "timezone", "screen", "cores", "memory", "fontCount",
                        "canvasRandomized", "webrtcIps", "fonts")
                summary = {k: clean_signal(signals.get(k)) for k in keep if k in signals}
                webgl = signals.get("webgl")
                if isinstance(webgl, dict):
                    summary["webgl_renderer"] = clean_signal(webgl.get("renderer"))
            except Exception:
                pass
            self._respond(204, "text/plain; charset=utf-8", b"")
            self._record(path, query, b"", 204, "browser-check", signature="browser_check",
                         extra={"browser_fingerprint": fingerprint, "browser_signals": summary})
            return

        payload = self._read_file(BAIT_DIR, "browser-check.html", 200)
        self._respond(200, "text/html; charset=utf-8", payload if send_body else b"")
        self._record(path, query, b"", 200, "browser-check", signature="benign")

    def _static_asset(self, path: str) -> str | None:
        """Relative filename for an existing static asset in the theme, else None."""
        if Path(path).suffix.lower() not in ASSET_EXTS:
            return None
        rel = path.lstrip("/")
        root = self.state.theme.root
        try:
            candidate = (root / rel).resolve()
            candidate.relative_to(root)
            return rel if candidate.is_file() else None
        except (OSError, ValueError):
            return None

    @staticmethod
    def _read_file(root: Path, filename: str, status: int) -> bytes:
        candidate = (root / filename).resolve()
        try:
            # Stay inside root (the theme or the bait dir); never serve an arbitrary path.
            candidate.relative_to(root.resolve())
            return candidate.read_bytes()
        except (OSError, ValueError):
            return f"<!doctype html><title>{status}</title><h1>{status}</h1>".encode()

    def _respond(self, status: int, content_type: str, body: bytes, cache_control: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if cache_control:
            self.send_header("Cache-Control", cache_control)
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _record(self, path: str, query: str, raw_body: bytes, status: int, decoy: str,
                signature: str | None = None, extra: dict | None = None) -> None:
        peer_port = self.client_address[1]
        src_ip = client_ip(self.client_address[0], self.headers.get("X-Forwarded-For"), self.state.trusted_proxy)

        # Flood cap: once a source is over its per-minute quota, count the hit
        # (for the suppressed-flood summary) and skip building the full event.
        if not self.state.should_ship(src_ip):
            return

        # What the client sent decides the label (classify, below); what is
        # kept has every credential masked: secret headers, form fields, the
        # body they came from and secret query parameters.
        common, key = self.state.common_passwords, self.state.password_key
        headers = kept_headers(list(self.headers.items()), common, key)
        header_map = dict(headers)
        header_names = [k for k, _ in headers]
        user_agent = self.headers.get("User-Agent", "")
        content_type = self.headers.get("Content-Type", "")
        accept = self.headers.get("Accept", "")
        accept_encoding = self.headers.get("Accept-Encoding", "")
        accept_language = self.headers.get("Accept-Language", "")

        # Passive shape signals: client hints and fetch-metadata a real browser
        # sends, and a stable fingerprint of the request's shape.
        client_hints = {k: v for k, v in header_map.items() if k.lower().startswith("sec-ch-")}
        sec_fetch = {k: v for k, v in header_map.items() if k.lower().startswith("sec-fetch-")}
        fingerprint = http_fingerprint(
            self.command, self.request_version, header_names, accept, accept_encoding, accept_language
        )

        form = mask_form(parse_form(raw_body, content_type), common, key)
        body_text = raw_body.decode("utf-8", "replace")
        body_excerpt = mask_body(body_text, form)
        kept_query = mask_query(query, common, key)

        local_ip, local_port = self.connection.getsockname()[:2]

        if signature is None:
            theme = self.state.theme
            signature = classify(self.command, path, query, body_text, user_agent, theme.pages, theme.logins)

        raw = {
            "method": self.command,
            "path": path[:HEADER_VALUE_CAP],
            "query": kept_query[:HEADER_VALUE_CAP],
            "http_version": self.request_version,
            "host": self.headers.get("Host", "")[:HEADER_VALUE_CAP],
            "user_agent": user_agent[:HEADER_VALUE_CAP],
            "referer": mask_url(self.headers.get("Referer", ""), common, key)[:HEADER_VALUE_CAP],
            "accept": accept[:HEADER_VALUE_CAP],
            "accept_encoding": accept_encoding[:HEADER_VALUE_CAP],
            "accept_language": accept_language[:HEADER_VALUE_CAP],
            "client_hints": client_hints,
            "sec_fetch": sec_fetch,
            "http_fingerprint": fingerprint,
            "headers": header_map,
            "header_order": header_names,
            "form": form,
            "body_excerpt": body_excerpt,
            "signature": signature,
            "decoy": decoy,
            "status": status,
        }
        if is_login_attempt(self.command, path, self.state.theme.logins):
            raw["login_attempt"] = True
        # Sent by a browser on behalf of another site's page: never bans.
        if is_cross_site(self.headers.get("Host", ""), self.headers.get("Referer", ""), user_agent,
                         self.headers.get("Sec-Fetch-Site", "")):
            raw["cross_site"] = True
        if extra:
            raw.update(extra)

        self.state.add(make_event(
            "honeypot_http", src_ip, local_ip if is_ip(local_ip) else "127.0.0.1",
            src_port=peer_port, dst_port=local_port, raw=raw,
        ))


# Any other verb a prober might try is a probe too: answered like a GET and
# recorded. (http.server calls do_<VERB>; a verb with no method gets Python's
# own 501 page and would leave no record.) A fixed list, so the method stored
# with an event is always one of these names.
PROBE_VERBS = ("PUT", "DELETE", "OPTIONS", "PATCH", "PROPFIND", "PROPPATCH", "MKCOL", "MOVE", "COPY",
               "LOCK", "UNLOCK", "TRACE", "TRACK", "CONNECT", "SEARCH")
for _verb in PROBE_VERBS:
    setattr(DecoyHandler, f"do_{_verb}", DecoyHandler.do_POST)


def main() -> int:
    try:
        state = _State()
    except (OSError, ValueError, KeyError) as error:
        print(f"cannot load the decoy theme: {error}", file=sys.stderr)
        return 2
    if state.outbox is None:
        return 2

    listen = os.environ.get("DECOY_LISTEN", "127.0.0.1:8088")
    host, _, port = listen.rpartition(":")
    server = ThreadingHTTPServer((host or "127.0.0.1", int(port)), DecoyHandler)
    DecoyHandler.state = state
    state.local_ip = host if (is_ip(host) and host != "0.0.0.0") else "127.0.0.1"
    state.local_port = int(port)

    stop = threading.Event()

    def sender() -> None:
        while not stop.is_set():
            state.wake.wait(FLUSH_SECONDS)   # a full batch, or every FLUSH_SECONDS
            state.wake.clear()
            state.flush()

    threading.Thread(target=sender, daemon=True).start()

    # shutdown() must run off the serve_forever thread, so hand it to a helper
    # thread rather than calling it from the signal handler directly.
    def terminate(*_: object) -> None:
        stop.set()
        state.wake.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, terminate)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        state.flush()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
