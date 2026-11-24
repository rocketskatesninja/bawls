"""The decoy end to end: real requests to a decoy on a local port, and exactly
what it would send to the console. Run with pytest from the sensors directory."""

import http.client
import json
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import decoy_sensor  # noqa: E402
import outbox  # noqa: E402
from decoy_sensor import DecoyHandler, _State, clean_signal, kept_headers, mask_header, mask_query, password_key  # noqa: E402

SECRET = "Zq7-real-Passw0rd!"


class Decoy:
    """A decoy on 127.0.0.1 whose events are collected instead of posted."""

    def __init__(self) -> None:
        self.sent: list[dict] = []
        state = _State()
        state.outbox = outbox.Outbox("u", "t", post=self._collect)
        handler = type("Handler", (DecoyHandler,), {"state": state})
        self.state = state
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def _collect(self, url: str, token: str, events: list[dict]) -> str:
        outbox.encode({"events": events})   # must be encodable, as post_batch requires
        self.sent.extend(events)
        return outbox.SENT

    def request(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None) -> int:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        connection.request(method, path, body=body, headers=headers or {})
        status = connection.getresponse().status
        connection.close()
        return status

    def events(self, expect: int) -> list[dict]:
        """The events sent so far, once `expect` have been recorded. The decoy
        answers first and records after, so a request's event can trail its
        response; they're returned oldest request first."""
        deadline = time.monotonic() + 3
        while len(self.state.outbox) + len(self.sent) < expect and time.monotonic() < deadline:
            time.sleep(0.01)
        self.state.flush()
        return sorted(self.sent, key=lambda event: event["occurred_at"])

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def decoy(monkeypatch):
    monkeypatch.setenv("TRIPWIRE_TOKEN", "test-token")
    running = Decoy()
    yield running
    running.close()


def test_a_typed_password_is_stored_nowhere_in_the_event(decoy):
    form = f"log=bob&pwd={SECRET}&wp-submit=Log+In".encode()
    decoy.request("POST", f"/wp-login.php?redirect_to=%2F&password={SECRET}", form, {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {SECRET}",
        "Cookie": f"session={SECRET}; theme=dark",
        "X-Api-Key": SECRET,
        "Referer": f"https://example.com/login?token={SECRET}&next=/",
    })

    [event] = decoy.events(1)
    raw = event["raw"]
    assert SECRET not in json.dumps(event)
    # What's kept still tells the story: who, where, and a fingerprint to count repeats.
    assert raw["form"]["log"] == "bob" and raw["form"]["pwd"].startswith("[masked:18 chars #")
    assert raw["body_excerpt"].startswith("log=bob&pwd=%5Bmasked")
    assert raw["query"].startswith("redirect_to=%2F&password=%5Bmasked")
    assert raw["headers"]["Authorization"] == "Basic [masked:18 chars]"
    assert raw["headers"]["Cookie"] == "session=[masked]; theme=[masked]"
    assert raw["headers"]["X-Api-Key"] == "[masked:18 chars]"
    assert raw["referer"].startswith("https://example.com/login?token=%5Bmasked")
    assert raw["login_attempt"] is True and raw["signature"] == "login"


def test_a_common_password_and_an_ordinary_query_are_kept_as_sent(decoy):
    decoy.request("POST", "/wp-login.php", b"log=admin&pwd=123456", {"Content-Type": "application/x-www-form-urlencoded"})
    decoy.request("GET", "/?url=.env&x=%2e%2e")

    login, probe = decoy.events(2)
    assert login["raw"]["form"]["pwd"] == "123456" and login["raw"]["body_excerpt"] == "log=admin&pwd=123456"
    assert probe["raw"]["query"] == "url=.env&x=%2e%2e"


def test_a_burst_of_huge_headers_cant_stop_the_decoy_reporting(decoy, monkeypatch):
    monkeypatch.setattr(outbox, "BATCH_BYTES", 20_000)
    for _ in range(10):
        decoy.request("GET", "/", headers={f"X-{'n' * 300}-{i}": "\xff" * 500 for i in range(40)})
    decoy.request("GET", "/after")

    events = decoy.events(11)
    assert len(events) == 11 and events[-1]["raw"]["path"] == "/after"
    for event in events:
        assert len(outbox.encode(event)) < 30_000
        assert all(len(name) <= decoy_sensor.HEADER_NAME_CAP for name in event["raw"]["headers"])


def test_static_assets_are_served_and_not_recorded(decoy):
    assert decoy.request("GET", "/assets/site.css") == 200
    assert decoy.request("GET", "/pricing") == 200
    assert [event["raw"]["path"] for event in decoy.events(1)] == ["/pricing"]


def test_header_masking_rules():
    key = password_key("t")
    assert mask_header("Authorization", "Bearer abc.def", set(), key) == "Bearer [masked:7 chars]"
    assert mask_header("authorization", "opaque", set(), key) == "[masked:6 chars]"
    assert mask_header("Cookie", "a=1; b=2", set(), key) == "a=[masked]; b=[masked]"
    assert mask_header("X-Auth-Token", "t0k3n", set(), key) == "[masked:5 chars]"
    assert mask_header("User-Agent", "curl/8", set(), key) == "curl/8"
    assert "s3cret" not in mask_header("Referer", "https://a.example/?token=s3cret", set(), key)
    kept = kept_headers([("A" * 500, "v")] + [(f"H{i}", "x" * 500) for i in range(60)], set(), key)
    assert len(kept[0][0]) == decoy_sensor.HEADER_NAME_CAP
    assert sum(len(n) + len(v) for n, v in kept) <= decoy_sensor.HEADERS_TOTAL_CAP


def test_query_masking_touches_only_secret_parameters():
    key = password_key("t")
    assert mask_query("a=1&b=%2e%2e", set(), key) == "a=1&b=%2e%2e"
    assert mask_query("user=bob&password=123456", {"123456"}, key) == "user=bob&password=123456"
    assert "hunter2xyz" not in mask_query("user=bob&api_key=hunter2xyz", set(), key)


def test_browser_check_signals_are_reduced_to_plain_values():
    assert clean_signal(float("nan")) is None and clean_signal(float("inf")) is None
    assert clean_signal({"nested": {"deep": 1}}) is None
    assert clean_signal("\ud800ok") == "?ok"
    assert clean_signal(["10.0.0.1", 5, "x" * 500]) == ["10.0.0.1", "x" * 100]
    assert clean_signal(8) == 8 and clean_signal(True) is True


def test_uncommon_verbs_are_probes_and_are_recorded(decoy):
    assert decoy.request("PROPFIND", "/") == 200
    assert decoy.request("PATCH", "/api/users/1", b"{}") == 404
    decoy.request("CONNECT", "example.com:443")

    events = decoy.events(3)
    assert [(e["raw"]["method"], e["raw"]["path"]) for e in events] == [
        ("PROPFIND", "/"), ("PATCH", "/api/users/1"), ("CONNECT", "example.com:443"),
    ]


def test_an_exploit_url_followed_from_another_site_is_marked_cross_site(decoy):
    browser = "Mozilla/5.0 (X11; Linux x86_64) Firefox/133.0"
    decoy.request("GET", "/?q=../../etc/passwd", headers={"User-Agent": browser, "Referer": "https://forum.example/thread/9"})
    decoy.request("GET", "/?q=../../etc/passwd", headers={"User-Agent": browser})

    planted, direct = decoy.events(2)
    assert planted["raw"]["signature"] == "traversal" and planted["raw"]["cross_site"] is True
    assert direct["raw"]["signature"] == "traversal" and "cross_site" not in direct["raw"]
