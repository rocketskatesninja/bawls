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
