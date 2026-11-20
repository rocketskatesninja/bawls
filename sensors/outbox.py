"""
Shipping events to the bawls ingest API, shared by the sensors.

Events wait in an Outbox and go out in batches of BATCH_MAX (the server takes
at most 500 per request). When ingest is unreachable, unsent events are kept
for the next flush, up to BACKLOG_MAX; past that the oldest are dropped, so an
outage can't grow a sensor's memory without bound, and a long backlog still
goes out in batches the server accepts.
"""

from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable

BATCH_MAX = 200
BACKLOG_MAX = 10_000


def post_batch(url: str, token: str, events: list[dict]) -> bool:
    """Send one batch to the ingest API. Returns True when it was accepted."""
    request = urllib.request.Request(
        f"{url.rstrip('/')}/api/ingest",
        data=json.dumps({"events": events}).encode(),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status in (200, 201)
    except urllib.error.HTTPError as error:
        detail = error.read()[:300].decode(errors="replace")
        print(f"ingest rejected: HTTP {error.code} {detail}", file=sys.stderr)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        print(f"ingest unreachable: {error}", file=sys.stderr)
    return False


class Outbox:
    """Events waiting to be sent. Safe to use from several threads."""

    def __init__(self, url: str, token: str,
                 post: Callable[[str, str, list[dict]], bool] = post_batch) -> None:
        self.url = url
        self.token = token
        self.post = post
        self.events: list[dict] = []
        self.lock = threading.Lock()

    def add(self, event: dict) -> bool:
        """Queue one event. True each time another full batch is waiting, so a
        backlog during an outage asks for a send every BATCH_MAX events, not on
        every one."""
        with self.lock:
            self.events.append(event)
            return len(self.events) % BATCH_MAX == 0

    def __len__(self) -> int:
        with self.lock:
            return len(self.events)

    def flush(self, extra: Iterable[dict] = ()) -> None:
        """Send everything waiting (plus extra) in batches; keep what didn't go."""
        with self.lock:
            pending, self.events = self.events + list(extra), []
        sent = 0
        while sent < len(pending):
            batch = pending[sent:sent + BATCH_MAX]
            if not self.post(self.url, self.token, batch):
                break
            sent += len(batch)
        if sent == len(pending):
            return
        with self.lock:
            self.events[:0] = pending[sent:]
            dropped = len(self.events) - BACKLOG_MAX
            if dropped > 0:
                del self.events[:dropped]
                print(f"ingest backlog full: dropped the {dropped} oldest event(s)", file=sys.stderr)
