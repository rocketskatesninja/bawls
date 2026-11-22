#!/usr/bin/env python3
"""Parser tests for the UFW sensor. Run: python3 sensors/test_ufw_sensor.py"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from ufw_sensor import parse_line  # noqa: E402

IGMP = (
    "2026-09-07T21:08:49-04:00 web1 kernel: [UFW BLOCK] IN=enp1s0 OUT= "
    "MAC=01:00:5e:00:00:01 SRC=10.0.0.254 DST=224.0.0.1 LEN=36 PROTO=2"
)
TCP_SCAN = (
    "2026-09-07T22:15:03-04:00 web1 kernel: [UFW BLOCK] IN=enp1s0 OUT= "
    "MAC=aa:bb SRC=203.0.113.7 DST=10.0.0.101 LEN=60 PROTO=TCP SPT=44321 DPT=445"
)
OUTBOUND = (
    "2026-09-07T22:16:00-04:00 web1 kernel: [UFW BLOCK] IN= OUT=enp1s0 "
    "SRC=10.0.0.101 DST=198.51.100.9 LEN=40 PROTO=UDP SPT=51000 DPT=53"
)
UTC_Z = (
    "2026-09-07T22:17:00Z web1 kernel: [UFW BLOCK] IN=enp1s0 OUT= "
    "SRC=203.0.113.8 DST=10.0.0.101 PROTO=TCP SPT=1 DPT=22"
)


def test_ignores_unrelated_lines():
    assert parse_line("2026-09-07T21:00:00-04:00 web1 kernel: something else") is None


def test_numeric_proto_maps_to_name():
    event = parse_line(IGMP)
    assert event["proto"] == "igmp"
    assert event["src_ip"] == "10.0.0.254"
    assert event["dst_port"] is None


def test_timestamp_uses_log_time_not_now():
    # Regression: journalctl short-iso emits "-04:00" (colon in offset).
    # An offset regex expecting "-0400" silently fell through to now().
    assert parse_line(IGMP)["occurred_at"].startswith("2026-09-08T01:08:49")


def test_tcp_ports_and_inbound_direction():
    event = parse_line(TCP_SCAN)
    assert event["proto"] == "tcp"
    assert event["src_port"] == 44321
    assert event["dst_port"] == 445
    assert event["direction"] == "in"
    assert event["iface"] == "enp1s0"


def test_outbound_direction_comes_from_out_field():
    event = parse_line(OUTBOUND)
    assert event["direction"] == "out"
    assert event["proto"] == "udp"
    assert event["dst_port"] == 53


def test_accepts_zulu_timestamps():
    assert parse_line(UTC_Z)["occurred_at"].startswith("2026-09-07T22:17:00")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for test in tests:
        test()
        print(f"  ok  {test.__name__}")
    print(f"\n{len(tests)} passed")
