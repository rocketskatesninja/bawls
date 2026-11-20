#!/usr/bin/env python3
"""
Bawls UFW sensor.

Follows the kernel journal for `[UFW BLOCK]` lines, normalises them, and
POSTs them to the bawls ingest API in batches (outbox.py).

Position is tracked by journalctl's own --cursor-file, so a restart resumes
where it left off instead of replaying or skipping the backlog.

Config comes from the environment (the TRIPWIRE_ names are the ingest
contract this sensor shares with tripwire):
    TRIPWIRE_URL     e.g. http://127.0.0.1:9119
    TRIPWIRE_TOKEN   ingest token from `php artisan bawls:sensor`
    TRIPWIRE_CURSOR  cursor file path (the installer uses /var/lib/bawls-ufw/ufw.cursor)

Usage:
    ufw_sensor.py                  follow the journal indefinitely
    ufw_sensor.py --since "1 hour ago"   backfill a range, then exit
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from outbox import Outbox

FLUSH_SECONDS = 5.0      # send partial batches this often
IP_PROTO = {"1": "icmp", "2": "igmp", "6": "tcp", "17": "udp"}

# `[UFW BLOCK] IN=enp1s0 OUT= MAC=.. SRC=1.2.3.4 DST=5.6.7.8 .. PROTO=TCP SPT=1 DPT=22`
FIELD_RE = re.compile(r"\b([A-Z]+)=(\S*)")
TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z))")


def parse_line(line: str) -> dict | None:
    """Turn one `[UFW BLOCK]` journal line into an ingest event, or None."""
    if "[UFW BLOCK]" not in line:
        return None

    ts_match = TS_RE.match(line)
    if ts_match:
        stamp = ts_match.group(1).replace("Z", "+00:00")
        occurred = datetime.fromisoformat(stamp)
    else:
        occurred = datetime.now(timezone.utc)

    fields = dict(FIELD_RE.findall(line.split("[UFW BLOCK]", 1)[1]))

    src, dst = fields.get("SRC"), fields.get("DST")
    if not src or not dst:
        return None

    proto_raw = (fields.get("PROTO") or "other").lower()
    proto = IP_PROTO.get(proto_raw, proto_raw)[:8]

    # UFW logs the interface a packet arrived on in IN= and the one it would
    # leave by in OUT=; exactly one is populated per direction.
    outbound = bool(fields.get("OUT"))

    def port(key: str) -> int | None:
        value = fields.get(key)
        return int(value) if value and value.isdigit() else None

    return {
        "occurred_at": occurred.astimezone(timezone.utc).isoformat(),
        "source": "ufw_block",
        "direction": "out" if outbound else "in",
        "proto": proto,
        "src_ip": src,
        "src_port": port("SPT"),
        "dst_ip": dst,
        "dst_port": port("DPT"),
        "iface": (fields.get("OUT") or fields.get("IN") or None),
        "action": "blocked",
    }




def _install_signal_handlers() -> None:
    """
    Flush the pending batch on SIGTERM.

    systemd stops and restarts services with SIGTERM, which by default
    kills Python outright — the buffered batch would be lost on every
    restart. Raising here lets the normal shutdown path run instead.
    """

    def terminate(signum: int, frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, terminate)


def main() -> int:
    url = os.environ.get("TRIPWIRE_URL", "http://127.0.0.1:9119")
    token = os.environ.get("TRIPWIRE_TOKEN", "")
    cursor = Path(os.environ.get("TRIPWIRE_CURSOR", "/var/lib/tripwire/ufw.cursor"))

    if not token:
        print("TRIPWIRE_TOKEN is not set", file=sys.stderr)
        return 2

    cursor.parent.mkdir(parents=True, exist_ok=True)

    since = None
    if "--since" in sys.argv:
        since = sys.argv[sys.argv.index("--since") + 1]

    command = ["journalctl", "-k", "-o", "short-iso", "--grep", r"\[UFW BLOCK\]"]
    if since:
        # Backfill mode: bounded read, no cursor, exits at the end of the range.
        command += ["--no-pager", "--since", since]
    else:
        command += ["-f", f"--cursor-file={cursor}"]

    # journalctl's own errors go straight to this unit's journal; a pipe nobody
    # read would fill up and stall it.
    process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True, bufsize=1)
    assert process.stdout is not None

    _install_signal_handlers()

    outbox = Outbox(url, token)
    last_flush = time.monotonic()

    try:
        for line in process.stdout:
            event = parse_line(line.strip())
            full = outbox.add(event) if event else False
            if full or (len(outbox) and time.monotonic() - last_flush >= FLUSH_SECONDS):
                outbox.flush()
                last_flush = time.monotonic()
    except KeyboardInterrupt:
        pass
    finally:
        outbox.flush()
        process.terminate()

    return 0


if __name__ == "__main__":
    sys.exit(main())
