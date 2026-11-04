"""Find suspicious IP addresses with Isolation Forest and compare with simple rules.

Run from the project folder:
  python src/model.py                                     -> test data, compared with labels
  python src/model.py data/pi_ssh.log                     -> real SSH log only, no labels
  python src/model.py data/pi_ssh.log data/pi_fw.log      -> real SSH + firewall log, no labels
Writes data/results.csv (test data) or data/results_real.csv (real logs)
"""
import sys

import pandas as pd
from sklearn.ensemble import IsolationForest

from log_parser import (ALL_FEATURES, build_features, build_firewall_features, combine_features,
                        parse_file, parse_firewall_file)

pd.set_option("display.max_columns", None)  # show all columns when printing
pd.set_option("display.width", 200)

# The columns (features) the model looks at: 4 from the SSH log + 2 from the firewall log.
FEATURE_COLUMNS = ALL_FEATURES

# Simple rules used for comparison:
FAILED_LIMIT = 5   # more than 5 failed logins           = brute-force
PORT_LIMIT = 10    # more than 10 different ports tried  = port scan


def features_to_table(features):
    """Turn {ip: {...}} into a pandas table with one row per IP."""
    table = pd.DataFrame.from_dict(features, orient="index")
    table.index.name = "ip"
    return table


def run_isolation_forest(table):
    """Train Isolation Forest on the table and return 1 (suspicious) or 0 (normal) per IP."""
    model = IsolationForest(contamination="auto", random_state=42)
    model.fit(table[FEATURE_COLUMNS])
    # predict() gives -1 for anomalies and 1 for normal; we turn that into 1 and 0.
    predictions = model.predict(table[FEATURE_COLUMNS])
    return (predictions == -1).astype(int)


def simple_rule(table):
    """Return 1 (suspicious) if an IP breaks one of the two rules, else 0."""
    brute_force = table["failed"] > FAILED_LIMIT
    port_scan = table["unique_ports"] > PORT_LIMIT
    return (brute_force | port_scan).astype(int)   # | means "or"


def load_features(ssh_path, firewall_path):
    """Read both logs and return one table. Without a firewall log, the firewall features are 0."""
    ssh = build_features(parse_file(ssh_path))
    firewall = build_firewall_features(parse_firewall_file(firewall_path)) if firewall_path else {}
    return features_to_table(combine_features(ssh, firewall))


def main():
    # Log files given on the command line are real data without labels.
    real_log = len(sys.argv) > 1
    if real_log:
        ssh_path = sys.argv[1]
        firewall_path = sys.argv[2] if len(sys.argv) > 2 else None
    else:
        ssh_path, firewall_path = "data/ssh_test.log", "data/firewall_test.log"

    table = load_features(ssh_path, firewall_path)
    if table.empty:
        raise SystemExit(f"No log lines found in {ssh_path} / {firewall_path}. Check the log format.")
    print(f"Read {len(table)} IP addresses from {ssh_path} and {firewall_path}\n")

    table["isolation_forest"] = run_isolation_forest(table)
    table["simple_rule"] = simple_rule(table)
    columns = FEATURE_COLUMNS + ["isolation_forest", "simple_rule"]

    if not real_log:
        # Add the answer key so we can see if the methods were right.
        labels = pd.read_csv("data/labels.csv", index_col="ip")
        table = table.join(labels)
        columns.append("label")

    table = table.sort_index()
    table.to_csv("data/results_real.csv" if real_log else "data/results.csv")

    print("IPs marked as suspicious by at least one method:\n")
    flagged = table[(table["isolation_forest"] == 1) | (table["simple_rule"] == 1)]
    print(flagged[columns])
    print(f"\nIsolation Forest marked {table['isolation_forest'].sum()} IPs, "
          f"simple rules marked {table['simple_rule'].sum()} IPs.")
    if not real_log:
        print(f"The answer key says {table['label'].sum()} are suspicious.")


if __name__ == "__main__":
    main()
