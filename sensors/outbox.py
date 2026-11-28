"""
Shipping events to the bawls ingest API, shared by the sensors.

Events wait in an Outbox and go out in batches of at most BATCH_MAX events and
BATCH_BYTES bytes (the server takes 500 events per request, and the web server
in front of it has a body-size limit). What happens to a batch depends on the
answer:

- accepted: gone.
- ingest unreachable, a server error, or "slow down" / "who are you" (5xx, 429,
  401, 403): kept for the next flush, in order.
- refused for what it contains (any other 4xx, such as 413 or 422): retrying
  the same bytes would fail forever and hold up everything behind it, so the
  batch is split in two to find the event the server won't take, and that
  event is dropped.

Unsent events are kept up to BACKLOG_MAX events and BACKLOG_BYTES bytes; past
either the oldest are dropped, so an outage can't grow a sensor's memory
without bound.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from datetime import datetime, timezone

BATCH_MAX = 200
BATCH_BYTES = 256_000
BACKLOG_MAX = 10_000
BACKLOG_BYTES = 32_000_000   # well under the sensors' MemoryMax

# What a post can answer.
SENT, RETRY, REFUSED = "sent", "retry", "refused"
RETRY_STATUSES = {401, 403, 408, 429}


def env_int(name: str, default: int) -> int:
    """An integer setting from the environment; unset or empty means default."""
    return int(os.environ.get(name) or default)


def is_ip(value: str) -> bool:
    """True when value parses as an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def block_of(ip: str) -> str:
    """
    The address the per-minute caps count against: an IPv4 address itself, or
    the first address of an IPv6 address's /64. One customer or server holds
    a whole /64 and can use a new address for every request, so counting each
    alone would cap nothing. (The console bans the same block: Network::block.)
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if address.version == 4:
        return ip
    return str(ipaddress.ip_network(f"{ip}/64", strict=False).network_address)


class RateCap:
    """
    At most `limit` events a minute per source (0 = no cap), shared by the
    sensors so a flood can't fill the database. A source is an address, or an
    IPv6 address's whole block (block_of). Safe to use from several threads.

    allow() answers for one event and counts what it turns away; drain()
    reports those counts (the decoy turns each into one "flood" summary
    event) and forgets sources from past minutes, so call it now and then
    even when the counts aren't wanted.
    """

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.lock = threading.Lock()
        # source -> [minute, events allowed in it, events turned away since the last drain]
        self.sources: dict[str, list[int]] = {}

    def allow(self, ip: str, now: float | None = None) -> bool:
        if self.limit <= 0:
            return True
        source = block_of(ip)
        minute = int((time.time() if now is None else now) // 60)
        with self.lock:
            entry = self.sources.get(source)
            if entry is None or entry[0] != minute:
                # A new minute starts the count afresh, but keeps what was
                # turned away and not yet reported.
                entry = self.sources[source] = [minute, 0, entry[2] if entry else 0]
            if entry[1] < self.limit:
                entry[1] += 1
                return True
            entry[2] += 1
            return False

    def drain(self, now: float | None = None) -> list[tuple[str, int]]:
        """[(source, events turned away)] since the last drain, for sources that had any."""
        minute = int((time.time() if now is None else now) // 60)
        turned_away = []
        with self.lock:
            for source, entry in list(self.sources.items()):
                if entry[2] > 0:
                    turned_away.append((source, entry[2]))
                    entry[2] = 0
                if entry[0] != minute:
                    del self.sources[source]   # stale: a fresh event re-creates it
        return turned_away


def make_event(source: str, src_ip: str, dst_ip: str, *, occurred_at: datetime | None = None,
               direction: str = "in", proto: str = "tcp", src_port: int | None = None,
               dst_port: int | None = None, action: str = "probed", **more: object) -> dict:
    """
    One event in the ingest API's format (App\\Http\\Controllers\\Api\\IngestController
    validates it; the format is shared with tripwire, the project bawls grew
    from). Every sensor builds its events here, so the format has one home:

        occurred_at  when it happened, UTC ISO 8601 (default: now)
        source       honeypot_http | site_http | ufw_block: must be one the
                     sensor's kind may report (App\\Models\\Sensor::SOURCES)
        direction    in | out
        proto        tcp, udp, icmp, ...
        src_ip, src_port, dst_ip, dst_port
        action       probed (an HTTP request) | blocked (the firewall)
        iface        optional: the network interface (UFW)
        raw          optional: the request's details, at most 64 KB as JSON
    """
    when = occurred_at or datetime.now(timezone.utc)
    return {
        "occurred_at": when.astimezone(timezone.utc).isoformat(),
        "source": source,
        "direction": direction,
        "proto": proto,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "action": action,
        **more,
    }


def encode(payload: object) -> bytes:
    """JSON as UTF-8 bytes. Raises ValueError for NaN or Infinity, which the
    server's JSON parser would refuse."""
    return json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8", "replace")


def post_batch(url: str, token: str, events: list[dict]) -> str:
    """Send one batch to the ingest API. Returns SENT, RETRY or REFUSED."""
    try:
        data = encode({"events": events})
    except (ValueError, TypeError) as error:
        print(f"ingest: batch can't be encoded: {error}", file=sys.stderr)
        return REFUSED
    request = urllib.request.Request(
        f"{url.rstrip('/')}/api/ingest",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return SENT if response.status in (200, 201) else RETRY
    except urllib.error.HTTPError as error:
        detail = error.read()[:300].decode(errors="replace")
        print(f"ingest rejected: HTTP {error.code} {detail}", file=sys.stderr)
        return REFUSED if 400 <= error.code < 500 and error.code not in RETRY_STATUSES else RETRY
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        print(f"ingest unreachable: {error}", file=sys.stderr)
        return RETRY


def size_of(event: dict) -> int:
    """An event's size on the wire, near enough; 0 if it can't be encoded
    (post_batch will refuse it, and it gets dropped there)."""
    try:
        return len(encode(event))
    except (ValueError, TypeError):
        return 0


class Outbox:
    """Events waiting to be sent. Safe to use from several threads."""

    def __init__(self, url: str, token: str,
                 post: Callable[[str, str, list[dict]], str | bool] = post_batch) -> None:
        self.url = url
        self.token = token
        self.post = post
        self.events: list[dict] = []
        self.sizes: list[int] = []   # each waiting event's size, same order
        self.lock = threading.Lock()

    @classmethod
    def from_env(cls) -> Outbox | None:
        """
        The outbox every sensor starts with: TRIPWIRE_URL (the console's
        ingest vhost on localhost) and TRIPWIRE_TOKEN. Says why and returns
        None when no token is set. (The names are tripwire's, the project
        bawls grew from; the two share this wire format.)
        """
        token = os.environ.get("TRIPWIRE_TOKEN", "")
        if not token:
            print("TRIPWIRE_TOKEN is not set", file=sys.stderr)
            return None
        return cls(os.environ.get("TRIPWIRE_URL", "http://127.0.0.1:9119"), token)

    def add(self, event: dict) -> bool:
        """Queue one event. True each time another full batch is waiting, so a
        backlog during an outage asks for a send every BATCH_MAX events, not on
        every one."""
        size = size_of(event)
        with self.lock:
            self.events.append(event)
            self.sizes.append(size)
            return len(self.events) % BATCH_MAX == 0

    def __len__(self) -> int:
        with self.lock:
            return len(self.events)

    def flush(self, extra: Iterable[dict] = ()) -> None:
        """Send everything waiting (plus extra) in batches; keep what didn't go."""
        extra = list(extra)
        with self.lock:
            pending, self.events = self.events + extra, []
            sizes, self.sizes = self.sizes + [size_of(e) for e in extra], []
        sent = 0
        while sent < len(pending):
            end = self._batch_end(sizes, sent)
            if not self._send(pending[sent:end]):
                break
            sent = end
        if sent == len(pending):
            return
        with self.lock:
            self.events[:0] = pending[sent:]
            self.sizes[:0] = sizes[sent:]
            dropped = self._overflow()
            if dropped:
                del self.events[:dropped]
                del self.sizes[:dropped]
                print(f"ingest backlog full: dropped the {dropped} oldest event(s)", file=sys.stderr)

    @staticmethod
    def _batch_end(sizes: list[int], start: int) -> int:
        """Where the batch starting at `start` ends: BATCH_MAX events or
        BATCH_BYTES bytes, whichever comes first (always at least one event)."""
        end, total = start, 0
        while end < len(sizes) and end - start < BATCH_MAX:
            total += sizes[end]
            if total > BATCH_BYTES and end > start:
                break
            end += 1
        return end

    def _send(self, batch: list[dict]) -> bool:
        """True when the batch is dealt with (sent, or refused and dropped);
        False when it should be tried again later."""
        answer = self.post(self.url, self.token, batch)
        if answer is True or answer == SENT:
            return True
        if answer != REFUSED:
            return False
        if len(batch) == 1:
            print("ingest: dropped 1 event the server refuses", file=sys.stderr)
            return True
        # Something in here is unacceptable: split to find it, keep the rest.
        middle = len(batch) // 2
        return self._send(batch[:middle]) and self._send(batch[middle:])

    def _overflow(self) -> int:
        """How many of the oldest waiting events must go to fit both limits."""
        drop = max(0, len(self.events) - BACKLOG_MAX)
        total = sum(self.sizes[drop:])
        while total > BACKLOG_BYTES and drop < len(self.sizes):
            total -= self.sizes[drop]
            drop += 1
        return drop
