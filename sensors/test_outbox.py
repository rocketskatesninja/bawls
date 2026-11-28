"""Tests for outbox.py: run with pytest from the sensors directory."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import outbox  # noqa: E402
from outbox import BATCH_MAX, Outbox  # noqa: E402


class FakeIngest:
    """Records batches; refuses from the given call on (1 = the first)."""

    def __init__(self, fail_from: int | None = None) -> None:
        self.batches: list[list[dict]] = []
        self.fail_from = fail_from

    def __call__(self, url: str, token: str, events: list[dict]) -> bool:
        if self.fail_from is not None and len(self.batches) + 1 >= self.fail_from:
            return False
        self.batches.append(events)
        return True


def events(n: int, start: int = 0) -> list[dict]:
    return [{"n": i} for i in range(start, start + n)]


def test_add_asks_for_a_send_once_per_full_batch():
    box = Outbox("u", "t", post=FakeIngest())
    asks = [box.add(e) for e in events(BATCH_MAX * 2 + 1)]
    assert [i + 1 for i, ask in enumerate(asks) if ask] == [BATCH_MAX, BATCH_MAX * 2]


def test_a_long_backlog_goes_out_in_batches_the_server_accepts():
    ingest = FakeIngest()
    box = Outbox("u", "t", post=ingest)
    for e in events(450):
        box.add(e)

    box.flush(extra=[{"n": "summary"}])

    assert [len(b) for b in ingest.batches] == [200, 200, 51]
    assert ingest.batches[2][-1] == {"n": "summary"}
    assert len(box) == 0


def test_what_did_not_go_is_kept_in_order_for_the_next_flush():
    box = Outbox("u", "t", post=FakeIngest(fail_from=2))
    for e in events(450):
        box.add(e)

    box.flush()

    assert len(box) == 250
    box.add({"n": "new"})
    assert box.events[0] == {"n": 200} and box.events[-1] == {"n": "new"}


def test_a_long_outage_drops_the_oldest_rather_than_growing_forever(monkeypatch):
    monkeypatch.setattr(outbox, "BACKLOG_MAX", 300)
    box = Outbox("u", "t", post=FakeIngest(fail_from=1))
    for e in events(450):
        box.add(e)

    box.flush()

    assert len(box) == 300
    assert box.events[0] == {"n": 150} and box.events[-1] == {"n": 449}


def test_nothing_waiting_sends_nothing():
    ingest = FakeIngest()
    Outbox("u", "t", post=ingest).flush()
    assert ingest.batches == []


class PickyIngest:
    """Accepts batches unless they hold an event marked bad."""

    def __init__(self) -> None:
        self.accepted: list[dict] = []
        self.calls = 0

    def __call__(self, url: str, token: str, events: list[dict]) -> str:
        self.calls += 1
        if any(e.get("bad") for e in events):
            return outbox.REFUSED
        self.accepted.extend(events)
        return outbox.SENT


def test_one_event_the_server_refuses_is_dropped_and_the_rest_still_go():
    ingest = PickyIngest()
    box = Outbox("u", "t", post=ingest)
    for i in range(300):
        box.add({"n": i, "bad": i == 137})

    box.flush()

    assert len(box) == 0
    assert [e["n"] for e in ingest.accepted] == [i for i in range(300) if i != 137]
    assert ingest.calls < 30   # found by halving, not one by one


def test_batches_are_limited_by_size_as_well_as_count(monkeypatch):
    monkeypatch.setattr(outbox, "BATCH_BYTES", 1000)
    ingest = FakeIngest()
    box = Outbox("u", "t", post=ingest)
    for i in range(6):
        box.add({"n": i, "pad": "x" * 400})

    box.flush()

    assert [len(b) for b in ingest.batches] == [2, 2, 2]


def test_an_event_bigger_than_a_batch_still_goes_alone(monkeypatch):
    monkeypatch.setattr(outbox, "BATCH_BYTES", 100)
    ingest = FakeIngest()
    box = Outbox("u", "t", post=ingest)
    box.add({"pad": "x" * 500})
    box.add({"n": 1})

    box.flush()

    assert [len(b) for b in ingest.batches] == [1, 1]


def test_the_backlog_is_bounded_in_bytes_too(monkeypatch):
    monkeypatch.setattr(outbox, "BACKLOG_BYTES", 5000)
    box = Outbox("u", "t", post=FakeIngest(fail_from=1))
    for i in range(50):
        box.add({"n": i, "pad": "x" * 480})   # about 500 bytes each

    box.flush()

    assert 8 <= len(box) <= 10
    assert box.events[-1]["n"] == 49 and len(box.sizes) == len(box.events)


def test_text_the_server_would_choke_on_is_sent_as_plain_utf8():
    assert outbox.encode({"ua": "ÿ" * 3}) == '{"ua": "ÿÿÿ"}'.encode()
    assert outbox.post_batch("http://127.0.0.1:9", "t", [{"cores": float("nan")}]) == outbox.REFUSED


def test_caps_count_an_ipv6_source_as_its_whole_block():
    assert outbox.block_of("203.0.113.9") == "203.0.113.9"
    assert outbox.block_of("2001:db8:1:2:aaaa:bbbb:cccc:7") == "2001:db8:1:2::"
    assert outbox.block_of("2001:db8:1:2::9") == outbox.block_of("2001:DB8:1:2:ffff::1")
    assert outbox.block_of("not-an-ip") == "not-an-ip"
