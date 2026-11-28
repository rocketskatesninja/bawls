#!/usr/bin/env python3
"""
Bawls real-site log sensor.

Follows the access logs of your real websites (SITE_LOGS) and sends the bawls
ingest API only the requests that match an exploit signature (signatures.py,
the same check the decoy uses), as `site_http` events. Every other line, your
visitors' ordinary traffic, is read and dropped here: it never leaves the log.

Logs are followed like `tail -F`: a rotated or truncated file is reopened, and
each file's position is saved, so a restart resumes where it stopped (reading
the rest of a file rotated meanwhile, from its `.1`). A file seen for the
first time starts at its end, so old history is never replayed.

Config (environment; the TRIPWIRE_ names are the ingest contract):
    TRIPWIRE_URL      ingest base URL (default http://127.0.0.1:9119)
    TRIPWIRE_TOKEN    sensor ingest token (required)
    SITE_LOGS         space-separated name=path pairs, e.g.
                      example.com=/var/log/apache2/example.com_ssl_access.log
    SITE_SERVER_IP    the address the sites answer on, recorded as destination
    SITE_STATE        positions file (default /var/lib/bawls-sites/positions.json)
    SITE_MAX_PER_MIN  events sent per source address per minute (default 120)
"""

from __future__ import annotations

import json
import os
import re
import signal
import sys
import threading
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

from outbox import Outbox, RateCap, env_int, is_ip, make_event
from signatures import EXPLOIT_SIGNATURES, SECRET_FIELD_RE, classify, is_cross_site

POLL_SECONDS = 1.0
FLUSH_SECONDS = 5.0
READ_CAP = 1 << 20          # bytes read per file per poll; the rest waits for the next
FIELD_CAP = 512             # chars kept per field, as the decoy keeps them

# Apache/nginx "combined" format; a quote inside the request line is logged as \".
LINE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}) \S+ "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)"'
)
SITE_NAME = re.compile(r"[A-Za-z0-9.-]{1,253}")


def parse_sites(value: str) -> list[tuple[str, str]]:
    """SITE_LOGS ("name=path name=path") as (name, path) pairs. A name may
    repeat (a site's http and https logs); a path may not. Raises ValueError."""
    sites: list[tuple[str, str]] = []
    for pair in value.split():
        name, sep, path = pair.partition("=")
        if not sep or not SITE_NAME.fullmatch(name) or not path.startswith("/"):
            raise ValueError(f"SITE_LOGS: expected name=/path, got {pair!r}")
        if any(path == seen for _, seen in sites):
            raise ValueError(f"SITE_LOGS: {path} is listed twice")
        sites.append((name, path))
    return sites


def mask_secrets(url_or_query: str) -> str:
    """
    A query string (or a URL with one) with the values of secret-looking
    parameters reduced to their length: an attack on a real site can carry a
    real visitor's ?token= or ?password= in its URL or Referer.
    """
    base, mark, query = url_or_query.rpartition("?")
    try:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    except ValueError:
        return url_or_query
    if not any(SECRET_FIELD_RE.search(name) for name, _ in pairs):
        return url_or_query
    masked = [(name, f"[masked:{len(value)} chars]" if SECRET_FIELD_RE.search(name) else value) for name, value in pairs]
    return base + mark + urllib.parse.urlencode(masked)


def to_event(line: str, site: str, server_ip: str) -> dict | None:
    """The ingest event for one log line, or None when it isn't an exploit attempt."""
    match = LINE.match(line)
    if not match:
        return None
    ip, stamp, request, status, referer, user_agent = match.groups()
    try:
        occurred = datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    if not is_ip(ip):
        return None
    method, _, rest = request.partition(" ")
    target = rest.rsplit(" ", 1)[0] if " " in rest else rest
    if not method or not target:
        return None
    parts = urllib.parse.urlsplit(target)
    path, query = parts.path or "/", parts.query
    signature = classify(method, path, query, "", user_agent)
    if signature not in EXPLOIT_SIGNATURES:
        return None
    raw_referer = "" if referer == "-" else referer
    return make_event(
        "site_http", ip, server_ip, occurred_at=occurred,
        raw={
            "site": site,
            "method": method[:16],
            "path": path[:FIELD_CAP],
            "query": mask_secrets(query)[:FIELD_CAP],
            "status": int(status),
            "user_agent": user_agent[:FIELD_CAP],
            "referer": "" if referer == "-" else mask_secrets(referer)[:FIELD_CAP],
            "signature": signature,
            # A log line has no Host, so the site's name stands in for it: name
            # a site by its domain in SITE_LOGS and a request that came by way
            # of another site's page is recorded without banning. A name that
            # isn't a domain can't be compared, so nothing counts as cross-site.
            **({"cross_site": True} if "." in site and is_cross_site(site, raw_referer, user_agent) else {}),
        },
    )


class Follower:
    """New complete lines from one log file, across rotation and truncation."""

    def __init__(self, path: str, saved: dict | None = None) -> None:
        self.path = path
        self.handle = None
        self.inode: int | None = None
        self.pending = b""
        self._start(saved)

    def _attach(self, path: str, inode: int, offset: int) -> None:
        if self.handle:
            self.handle.close()
        self.handle = open(path, "rb")
        self.handle.seek(offset)
        self.inode = inode
        self.pending = b""

    def _start(self, saved: dict | None) -> None:
        try:
            now = os.stat(self.path)
        except OSError:
            return   # not there yet: read it from its start once it appears
        if saved:
            # Resume at the saved spot, also in the file just rotated out of the way.
            for candidate in (self.path, self.path + ".1"):
                try:
                    st = os.stat(candidate)
                except OSError:
                    continue
                if st.st_ino == saved.get("inode"):
                    offset = saved.get("offset", 0)
                    self._attach(candidate, st.st_ino, offset if offset <= st.st_size else 0)
                    return
            self._attach(self.path, now.st_ino, 0)   # rotated twice while stopped
            return
        self._attach(self.path, now.st_ino, now.st_size)   # never seen: from now on

    def _drain(self) -> list[str]:
        if not self.handle:
            return []
        data = self.pending + self.handle.read(READ_CAP)
        *complete, self.pending = data.split(b"\n")
        return [line.decode("utf-8", "replace") for line in complete]

    def poll(self) -> list[str]:
        lines = self._drain()
        try:
            st = os.stat(self.path)
        except OSError:
            return lines   # mid-rotation: the new file isn't there yet
        if self.handle is None or st.st_ino != self.inode:
            self._attach(self.path, st.st_ino, 0)   # rotated (or new): its start
            lines += self._drain()
        elif st.st_size < self.handle.tell():
            self.handle.seek(0)                      # truncated in place (copytruncate)
            self.pending = b""
            lines += self._drain()
        return lines

    @property
    def position(self) -> dict | None:
        if not self.handle:
            return None
        return {"inode": self.inode, "offset": self.handle.tell() - len(self.pending)}


def load_positions(path: Path) -> dict:
    """Where each log was read up to last time ({} on a first run or a bad file)."""
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_positions(path: Path, positions: dict) -> None:
    """Written to a temporary file and renamed, so a crash can't leave half a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(positions))
    temporary.replace(path)


def main() -> int:
    outbox = Outbox.from_env()
    if outbox is None:
        return 2
    try:
        sites = parse_sites(os.environ.get("SITE_LOGS", ""))
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    if not sites:
        print("SITE_LOGS is empty: nothing to watch", file=sys.stderr)
        return 2
    server_ip = os.environ.get("SITE_SERVER_IP", "127.0.0.1")
    if not is_ip(server_ip):
        server_ip = "127.0.0.1"
    state = Path(os.environ.get("SITE_STATE", "/var/lib/bawls-sites/positions.json"))
    cap = RateCap(env_int("SITE_MAX_PER_MIN", 120))

    saved = load_positions(state)
    followers = [(name, Follower(path, saved.get(path))) for name, path in sites]
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    last_flush = time.monotonic()
    positions: dict = {}
    try:
        while not stop.is_set():
            for name, follower in followers:
                for line in follower.poll():
                    event = to_event(line, name, server_ip)
                    if event and cap.allow(event["src_ip"]) and outbox.add(event):
                        outbox.flush()
                        last_flush = time.monotonic()
            if len(outbox) and time.monotonic() - last_flush >= FLUSH_SECONDS:
                outbox.flush()
                last_flush = time.monotonic()
            current = {f.path: f.position for _, f in followers if f.position}
            if current != positions:
                save_positions(state, current)
                positions = current
            cap.drain()   # forget sources from past minutes; what it turned away isn't reported
            stop.wait(POLL_SECONDS)
    except KeyboardInterrupt:
        pass
    finally:
        outbox.flush()
        current = {f.path: f.position for _, f in followers if f.position}
        if current:
            save_positions(state, current)
    return 0


if __name__ == "__main__":
    sys.exit(main())
