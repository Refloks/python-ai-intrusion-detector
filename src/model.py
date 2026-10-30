"""Find suspicious IP addresses with Isolation Forest and compare with a simple rule.

Run from the project folder:  python src/model.py
Reads data/ssh_test.log and writes data/results.csv
"""
import pandas as pd
from sklearn.ensemble import IsolationForest

from log_parser import build_features, parse_file

pd.set_option("display.max_columns", None)  # show all columns when printing
pd.set_option("display.width", 200)

# The columns (features) the model looks at.
FEATURE_COLUMNS = ["failed", "accepted", "night_logins", "unique_users"]

# Simple rule used for comparison: more than this many failed logins = suspicious.
FAILED_LIMIT = 5


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
    """Return 1 (suspicious) if an IP has more than FAILED_LIMIT failed logins, else 0."""
    return (table["failed"] > FAILED_LIMIT).astype(int)


def main():
    table = features_to_table(build_features(parse_file("data/ssh_test.log")))

    table["isolation_forest"] = run_isolation_forest(table)
    table["simple_rule"] = simple_rule(table)

    # Add the answer key so we can see if the methods were right.
    labels = pd.read_csv("data/labels.csv", index_col="ip")
    table = table.join(labels)

    table.to_csv("data/results.csv")

    print("IPs marked as suspicious by at least one method:\n")
    flagged = table[(table["isolation_forest"] == 1) | (table["simple_rule"] == 1)]
    print(flagged[FEATURE_COLUMNS + ["isolation_forest", "simple_rule", "label"]])
    print(f"\nIsolation Forest marked {table['isolation_forest'].sum()} IPs, "
          f"simple rule marked {table['simple_rule'].sum()} IPs, "
          f"answer key says {table['label'].sum()} are suspicious.")


if __name__ == "__main__":
    main()
