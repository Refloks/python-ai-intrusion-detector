"""Generate test SSH logs (normal activity + simulated attacks) and an answer key.

Run from the project folder:  python src/generate_logs.py
Creates two files:
  data/ssh_test.log  - log lines in the same style as sshd on Fedora
  data/labels.csv    - for each IP: normal (0) or suspicious (1)?
"""
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

# The same seed gives the same "random" numbers every time -> the same test data every time.
random.seed(42)

START = datetime(2026, 10, 1)
DAYS = 7

# Normal users: each user logs in from their own IP during working hours.
NORMAL_USERS = {"192.168.1.10": "anna", "192.168.1.11": "bo", "192.168.1.12": "carl"}

# Attackers (IP addresses from ranges reserved for documentation/examples).
BRUTE_FORCE_IPS = ["203.0.113.5", "203.0.113.77"]
NIGHT_IP = "198.51.100.23"  # logs in at night with a real user's account


def random_port():
    """A random client port, as in real logs."""
    return random.randint(40000, 60000)


def normal_activity():
    """Every day: one login per user between 8:00 and 17:00. Sometimes a typo first."""
    lines = []
    for day in range(DAYS):
        for ip, user in NORMAL_USERS.items():
            time = START + timedelta(days=day, hours=random.randint(8, 16),
                                     minutes=random.randint(0, 59))
            if random.random() < 0.2:  # 20 % chance of a typo
                lines.append((time, f"Failed password for {user} from {ip} port {random_port()} ssh2"))
                time += timedelta(seconds=15)
            lines.append((time, f"Accepted password for {user} from {ip} port {random_port()} ssh2"))
    return lines


def brute_force():
    """Each attacker tries 30-60 times within a few minutes using common usernames."""
    lines = []
    for ip in BRUTE_FORCE_IPS:
        time = START + timedelta(days=random.randint(0, DAYS - 1),
                                 hours=random.randint(0, 23))
        for _ in range(random.randint(30, 60)):
            user = random.choice(["root", "admin", "test"])
            lines.append((time, f"Failed password for {user} from {ip} port {random_port()} ssh2"))
            time += timedelta(seconds=random.randint(1, 5))
    return lines


def night_logins():
    """An unknown IP logs in as 'bo' between 2:00 and 4:00 on three different nights."""
    lines = []
    for day in random.sample(range(DAYS), 3):
        time = START + timedelta(days=day, hours=random.randint(2, 3),
                                 minutes=random.randint(0, 59))
        lines.append((time, f"Accepted password for bo from {NIGHT_IP} port {random_port()} ssh2"))
    return lines


def format_line(time, text):
    """Turn (time, text) into a log line, e.g. 'Oct 03 14:05:22 fedora sshd[4821]: ...'"""
    return f"{time.strftime('%b %d %H:%M:%S')} fedora sshd[{random.randint(1000, 9999)}]: {text}"


def main():
    all_lines = normal_activity() + brute_force() + night_logins()
    all_lines.sort()  # sort by time so it looks like a real log file

    folder = Path("data")
    folder.mkdir(exist_ok=True)

    with open(folder / "ssh_test.log", "w") as f:
        for time, text in all_lines:
            f.write(format_line(time, text) + "\n")

    with open(folder / "labels.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "label", "type"])
        for ip in NORMAL_USERS:
            writer.writerow([ip, 0, "normal"])
        for ip in BRUTE_FORCE_IPS:
            writer.writerow([ip, 1, "brute_force"])
        writer.writerow([NIGHT_IP, 1, "unusual_time"])

    print(f"Wrote {len(all_lines)} log lines to data/ssh_test.log and labels to data/labels.csv")


if __name__ == "__main__":
    main()
