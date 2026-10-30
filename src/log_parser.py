"""Read SSH log lines and turn them into features per IP address.

Two steps:
  1. parse_line()     - one log line  -> a dict with time, status, user and ip
  2. build_features() - all events    -> one row of numbers per IP (the model's input)
"""
import re
from datetime import datetime

# Matches lines like:
# Oct 01 09:01:00 fedora sshd[2753]: Accepted password for anna from 192.168.1.10 port 48024 ssh2
LINE_PATTERN = re.compile(
    r"^(?P<time>\w{3} \d{2} \d{2}:\d{2}:\d{2}) .*sshd\[\d+\]: "
    r"(?P<status>Accepted|Failed) password for (?P<user>\S+) "
    r"from (?P<ip>\S+) port \d+"
)

NIGHT_START = 0  # logins from 00:00 ...
NIGHT_END = 6    # ... up to 05:59 count as night logins


def parse_line(line, year=2026):
    """Return a dict for a login line, or None if the line is not a login line."""
    match = LINE_PATTERN.match(line)
    if match is None:
        return None
    # The log has no year, so we add it ourselves.
    time = datetime.strptime(f"{year} {match['time']}", "%Y %b %d %H:%M:%S")
    return {
        "time": time,
        "status": match["status"],   # "Accepted" or "Failed"
        "user": match["user"],
        "ip": match["ip"],
    }


def parse_file(path):
    """Read a log file and return a list of events (lines we could not read are skipped)."""
    events = []
    with open(path) as f:
        for line in f:
            event = parse_line(line)
            if event is not None:
                events.append(event)
    return events


def build_features(events):
    """Count, for each IP, the numbers the model will look at."""
    features = {}
    for event in events:
        ip = event["ip"]
        if ip not in features:
            features[ip] = {"failed": 0, "accepted": 0, "night_logins": 0, "users": set()}
        row = features[ip]

        if event["status"] == "Failed":
            row["failed"] += 1
        else:
            row["accepted"] += 1
            if NIGHT_START <= event["time"].hour < NIGHT_END:
                row["night_logins"] += 1
        row["users"].add(event["user"])

    # Replace the set of usernames with how many different usernames were tried.
    for row in features.values():
        row["unique_users"] = len(row.pop("users"))
    return features


if __name__ == "__main__":
    for ip, row in build_features(parse_file("data/ssh_test.log")).items():
        print(ip, row)
