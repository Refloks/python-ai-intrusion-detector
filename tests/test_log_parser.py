from datetime import datetime

from log_parser import build_features, parse_line

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
