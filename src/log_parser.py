"""Read SSH and firewall log lines and turn them into features per IP address.

Steps:
  1. parse_line() / parse_firewall_line()            - one log line -> a small dict
  2. build_features() / build_firewall_features()    - all events   -> numbers per IP
  3. combine_features()                              - both logs    -> one row per IP (the model's input)
"""
import re
from datetime import datetime

# Matches lines like:
# Oct 01 09:01:00 fedora sshd[2753]: Accepted password for anna from 192.168.1.10 port 48024 ssh2
# Real logs also contain these variants, which we must handle too:
#   sshd-session[...]                (newer OpenSSH versions use this process name)
#   Accepted publickey for ...       (login with an SSH key instead of a password)
#   Failed password for invalid user admin from ...   (username does not exist)
LINE_PATTERN = re.compile(
    r"^(?P<time>\w{3} [ \d]\d \d{2}:\d{2}:\d{2}) .*sshd(-session)?\[\d+\]: "
    r"(?P<status>Accepted|Failed) (password|publickey) for (invalid user )?(?P<user>\S+) "
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


# ---------- Firewall (UFW) log ----------

# Matches blocked packets like:
# Nov 03 22:50:01 pi-server kernel: [UFW BLOCK] IN=eth0 OUT= ... SRC=10.0.0.171 DST=10.0.0.16 ... DPT=443 ...
# Some packets (e.g. ping/ICMP) have no destination port, so DPT is optional.
FIREWALL_PATTERN = re.compile(r"\[UFW BLOCK\] .*?SRC=(?P<ip>\S+)(?: .*?DPT=(?P<port>\d+))?")


def parse_firewall_line(line):
    """Return {"ip": ..., "port": ...} for a blocked packet, or None for any other line."""
    match = FIREWALL_PATTERN.search(line)
    if match is None:
        return None
    port = int(match["port"]) if match["port"] else None
    return {"ip": match["ip"], "port": port}


def parse_firewall_file(path):
    """Read a firewall log and return a list of blocked packets."""
    events = []
    with open(path) as f:
        for line in f:
            event = parse_firewall_line(line)
            if event is not None:
                events.append(event)
    return events


def build_firewall_features(events):
    """Count, for each IP, how many packets were blocked and how many different ports it tried."""
    features = {}
    for event in events:
        ip = event["ip"]
        if ip not in features:
            features[ip] = {"blocked": 0, "ports": set()}
        row = features[ip]
        row["blocked"] += 1
        if event["port"] is not None:
            row["ports"].add(event["port"])
    for row in features.values():
        row["unique_ports"] = len(row.pop("ports"))
    return features


# ---------- Combine both logs ----------

ALL_FEATURES = ["failed", "accepted", "night_logins", "unique_users", "blocked", "unique_ports"]


def combine_features(ssh_features, firewall_features):
    """One row per IP with all features. An IP that is only in one log gets 0 for the other log's features."""
    combined = {}
    for ip in set(ssh_features) | set(firewall_features):   # every IP from both logs
        row = {name: 0 for name in ALL_FEATURES}
        row.update(ssh_features.get(ip, {}))
        row.update(firewall_features.get(ip, {}))
        combined[ip] = row
    return combined


if __name__ == "__main__":
    ssh = build_features(parse_file("data/ssh_test.log"))
    firewall = build_firewall_features(parse_firewall_file("data/firewall_test.log"))
    for ip, row in sorted(combine_features(ssh, firewall).items()):
        print(ip, row)
