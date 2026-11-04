"""Generate test logs (normal activity + simulated attacks) and an answer key.

Run from the project folder:  python src/generate_logs.py
Creates three files:
  data/ssh_test.log       - SSH log lines in the same style as sshd
  data/firewall_test.log  - blocked packets in the same style as the UFW firewall on Ubuntu
  data/labels.csv         - for each IP: normal (0) or suspicious (1)?
"""
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

# The same seed gives the same "random" numbers every time -> the same test data every time.
random.seed(42)

START = datetime(2026, 10, 1)
DAYS = 7

# 35 normal users: user01 logs in from 192.168.1.10, user02 from 192.168.1.11, and so on.
NORMAL_USERS = {f"192.168.1.{10 + n}": f"user{n + 1:02d}" for n in range(35)}

# Attackers (IP addresses from ranges reserved for documentation/examples).
BRUTE_FORCE_IPS = ["203.0.113.5", "203.0.113.77", "203.0.113.140"]
NIGHT_IPS = ["198.51.100.23", "198.51.100.88"]  # log in at night with a real user's account


def random_port():
    """A random client port, as in real logs."""
    return random.randint(40000, 60000)


def random_time(day, first_hour, last_hour):
    """A random time on the given day between first_hour and last_hour (incl. seconds)."""
    return START + timedelta(days=day, hours=random.randint(first_hour, last_hour),
                             minutes=random.randint(0, 59), seconds=random.randint(0, 59))


def normal_activity():
    """Each user logs in 0-3 times a day between 7:00 and 18:00, and sometimes types the password wrong.

    Users are different: some make many typos, others almost never.
    """
    lines = []
    for ip, user in NORMAL_USERS.items():
        typo_chance = random.uniform(0, 0.3)  # this user's chance of a typo (0-30 %)
        for day in range(DAYS):
            for _ in range(random.randint(0, 3)):
                time = random_time(day, 7, 17)
                if random.random() < typo_chance:
                    lines.append((time, f"Failed password for {user} from {ip} port {random_port()} ssh2"))
                    time += timedelta(seconds=random.randint(5, 30))
                lines.append((time, f"Accepted password for {user} from {ip} port {random_port()} ssh2"))
    return lines


def brute_force():
    """Each attacker tries 20-60 times within a few minutes using common usernames."""
    lines = []
    for ip in BRUTE_FORCE_IPS:
        time = random_time(random.randint(0, DAYS - 1), 0, 23)
        for _ in range(random.randint(20, 60)):
            user = random.choice(["root", "admin", "test", "oracle", "pi"])
            lines.append((time, f"Failed password for {user} from {ip} port {random_port()} ssh2"))
            time += timedelta(seconds=random.randint(1, 5))
    return lines


def night_logins():
    """Each night IP logs in with a real user's account between 2:00 and 4:00 on 2-4 different nights."""
    lines = []
    for ip in NIGHT_IPS:
        user = random.choice(list(NORMAL_USERS.values()))  # a stolen password
        for day in random.sample(range(DAYS), random.randint(2, 4)):
            time = random_time(day, 2, 3)
            lines.append((time, f"Accepted password for {user} from {ip} port {random_port()} ssh2"))
    return lines


def format_line(time, text):
    """Turn (time, text) into a log line, e.g. 'Oct 03 14:05:22 fedora sshd[4821]: ...'"""
    return f"{time.strftime('%b %d %H:%M:%S')} fedora sshd[{random.randint(1000, 9999)}]: {text}"


# ---------- Firewall (UFW) log ----------

SERVER_IP = "192.168.1.2"
PORT_SCAN_IPS = ["192.0.2.50", "198.51.100.200"]  # only scan ports, never try to log in
SCAN_THEN_BRUTE_FORCE_IP = "203.0.113.5"            # scans first, then the brute-force in the SSH log
NOISE_PORTS = [137, 138, 1900, 5353]                 # normal "chatter" on a home network (Windows, printers, ...)


def firewall_line(time, ip, port):
    """One blocked packet in the same style as UFW on Ubuntu."""
    return (f"{time.strftime('%b %d %H:%M:%S')} fedora kernel: [UFW BLOCK] IN=eth0 OUT= "
            f"SRC={ip} DST={SERVER_IP} LEN=44 TTL=64 PROTO=TCP SPT={random_port()} DPT={port} SYN")


def normal_firewall_noise():
    """About a third of the normal users have 1-3 harmless blocked packets during the week."""
    lines = []
    for ip in NORMAL_USERS:
        if random.random() < 0.33:
            for _ in range(random.randint(1, 3)):
                lines.append((random_time(random.randint(0, DAYS - 1), 7, 17), ip, random.choice(NOISE_PORTS)))
    return lines


def port_scan(ip, start, number_of_ports):
    """Try many different ports very fast, like the tool nmap does."""
    lines = []
    time = start
    for port in random.sample(range(1, 10000), number_of_ports):
        lines.append((time, ip, port))
        time += timedelta(milliseconds=random.randint(10, 300))
    return lines


def firewall_activity(ssh_lines):
    """Noise from normal users + two port scanners + a scan right before one of the brute-force attacks."""
    lines = normal_firewall_noise()
    for ip in PORT_SCAN_IPS:
        lines += port_scan(ip, random_time(random.randint(0, DAYS - 1), 0, 23), random.randint(100, 1000))

    # Find when the brute-force from SCAN_THEN_BRUTE_FORCE_IP starts, and scan 10 minutes before.
    attack_start = min(time for time, text in ssh_lines if f"from {SCAN_THEN_BRUTE_FORCE_IP} " in text)
    lines += port_scan(SCAN_THEN_BRUTE_FORCE_IP, attack_start - timedelta(minutes=10), 50)
    return lines


def main():
    all_lines = normal_activity() + brute_force() + night_logins()
    all_lines.sort()  # sort by time so it looks like a real log file

    folder = Path("data")
    folder.mkdir(exist_ok=True)

    with open(folder / "ssh_test.log", "w") as f:
        for time, text in all_lines:
            f.write(format_line(time, text) + "\n")

    # The firewall log is made AFTER the SSH log, so the SSH log stays exactly as before.
    firewall_lines = sorted(firewall_activity(all_lines))
    with open(folder / "firewall_test.log", "w") as f:
        for time, ip, port in firewall_lines:
            f.write(firewall_line(time, ip, port) + "\n")

    with open(folder / "labels.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "label", "type"])
        for ip in NORMAL_USERS:
            writer.writerow([ip, 0, "normal"])
        for ip in BRUTE_FORCE_IPS:
            kind = "port_scan_and_brute_force" if ip == SCAN_THEN_BRUTE_FORCE_IP else "brute_force"
            writer.writerow([ip, 1, kind])
        for ip in NIGHT_IPS:
            writer.writerow([ip, 1, "unusual_time"])
        for ip in PORT_SCAN_IPS:
            writer.writerow([ip, 1, "port_scan"])

    print(f"Wrote {len(all_lines)} lines to data/ssh_test.log, "
          f"{len(firewall_lines)} lines to data/firewall_test.log and labels to data/labels.csv")


if __name__ == "__main__":
    main()
