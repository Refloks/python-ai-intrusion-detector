from datetime import datetime

from log_parser import build_features, build_firewall_features, combine_features, parse_firewall_line, parse_line

ACCEPTED = "Oct 01 09:01:00 fedora sshd[2753]: Accepted password for anna from 192.168.1.10 port 48024 ssh2"
FAILED = "Oct 02 08:35:00 fedora sshd[5616]: Failed password for root from 203.0.113.5 port 57856 ssh2"


def test_parse_accepted_line():
    event = parse_line(ACCEPTED)
    assert event["status"] == "Accepted"
    assert event["user"] == "anna"
    assert event["ip"] == "192.168.1.10"
    assert event["time"] == datetime(2026, 10, 1, 9, 1, 0)


def test_parse_failed_line():
    event = parse_line(FAILED)
    assert event["status"] == "Failed"
    assert event["user"] == "root"


def test_other_lines_are_ignored():
    assert parse_line("Oct 01 09:01:00 fedora sshd[1]: Server listening on 0.0.0.0 port 22.") is None
    assert parse_line("") is None


def test_real_log_variants_are_understood():
    """Variants seen in real SSH logs, which our generated test data does not contain."""
    invalid = "Nov 03 10:12:01 raspberrypi sshd[812]: Failed password for invalid user admin from 192.168.1.50 port 51000 ssh2"
    key = "Nov 03 10:13:00 raspberrypi sshd[815]: Accepted publickey for pi from 192.168.1.50 port 51002 ssh2: ED25519 SHA256:abc"
    session = "Nov 03 10:14:00 fedora sshd-session[900]: Failed password for root from 10.0.0.9 port 4000 ssh2"
    single_digit_day = "Nov  3 10:15:00 raspberrypi sshd[820]: Failed password for pi from 192.168.1.50 port 51003 ssh2"

    assert parse_line(invalid)["user"] == "admin"
    assert parse_line(key)["status"] == "Accepted"
    assert parse_line(session)["ip"] == "10.0.0.9"
    assert parse_line(single_digit_day)["time"] == datetime(2026, 11, 3, 10, 15, 0)


def test_build_features_counts_per_ip():
    events = [parse_line(FAILED), parse_line(FAILED), parse_line(ACCEPTED)]
    features = build_features(events)
    assert features["203.0.113.5"]["failed"] == 2
    assert features["192.168.1.10"]["accepted"] == 1
    assert features["192.168.1.10"]["night_logins"] == 0


def test_night_login_is_counted():
    night = "Oct 03 02:15:00 fedora sshd[1]: Accepted password for bo from 198.51.100.23 port 50000 ssh2"
    features = build_features([parse_line(night)])
    assert features["198.51.100.23"]["night_logins"] == 1


# ---------- Firewall ----------

UFW_TCP = ("Nov 03 22:50:01 pi-server kernel: [UFW BLOCK] IN=eth0 OUT= MAC=b8:27:eb:00:00:01 "
           "SRC=10.0.0.171 DST=10.0.0.16 LEN=44 TOS=0x00 PREC=0x00 TTL=42 ID=1 PROTO=TCP SPT=54321 DPT=443 "
           "WINDOW=1024 RES=0x00 SYN URGP=0")
UFW_PING = ("Nov 03 22:51:00 pi-server kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.171 DST=10.0.0.16 "
            "LEN=84 TTL=64 PROTO=ICMP TYPE=8 CODE=0 ID=7 SEQ=1")


def test_parse_firewall_line():
    assert parse_firewall_line(UFW_TCP) == {"ip": "10.0.0.171", "port": 443}


def test_firewall_line_without_port():
    assert parse_firewall_line(UFW_PING) == {"ip": "10.0.0.171", "port": None}


def test_allowed_and_ssh_lines_are_not_firewall_blocks():
    assert parse_firewall_line(UFW_TCP.replace("UFW BLOCK", "UFW ALLOW")) is None
    assert parse_firewall_line(ACCEPTED) is None


def test_firewall_features_count_unique_ports():
    events = [{"ip": "a", "port": 22}, {"ip": "a", "port": 22}, {"ip": "a", "port": 80}, {"ip": "a", "port": None}]
    assert build_firewall_features(events) == {"a": {"blocked": 4, "unique_ports": 2}}


def test_combine_fills_missing_features_with_zero():
    ssh = {"1.1.1.1": {"failed": 3, "accepted": 0, "night_logins": 0, "unique_users": 1}}
    firewall = {"2.2.2.2": {"blocked": 9, "unique_ports": 9}}
    combined = combine_features(ssh, firewall)
    assert combined["1.1.1.1"]["blocked"] == 0
    assert combined["2.2.2.2"]["failed"] == 0
    assert combined["2.2.2.2"]["unique_ports"] == 9
