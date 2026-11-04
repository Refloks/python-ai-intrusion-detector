from datetime import datetime

from generate_logs import night_logins, port_scan


def test_night_logins_are_between_2_and_4():
    for time, text in night_logins():
        assert 2 <= time.hour < 4
        assert "Accepted password" in text


def test_port_scan_tries_different_ports_fast():
    packets = port_scan("192.0.2.50", datetime(2026, 10, 1, 12, 0), 100)
    ports = [port for time, ip, port in packets]
    assert len(set(ports)) == 100                                 # 100 different ports
    assert packets[-1][0] - packets[0][0] < (datetime(2026, 10, 1, 12, 1) - datetime(2026, 10, 1, 12, 0))  # within 1 minute
