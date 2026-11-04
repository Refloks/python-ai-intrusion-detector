"""Measure how good Isolation Forest and the simple rule are, compared with the answer key.

Run from the project folder (after src/model.py):  python src/validate.py
Reads data/results.csv and writes data/validation.csv
"""
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, precision_score, recall_score

from model import FEATURE_COLUMNS

METHODS = ["isolation_forest", "simple_rule"]
COUNT_COLUMNS = ["true_positives", "false_positives", "false_negatives", "true_negatives"]


def evaluate(labels, predictions):
    """Compare predictions (0/1) with the true labels (0/1) and return the numbers we care about."""
    # confusion_matrix gives [[TN, FP], [FN, TP]]; ravel() turns it into one flat list.
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    return {
        "true_positives": tp,    # suspicious, and the method said suspicious (correct)
        "false_positives": fp,   # normal, but the method said suspicious (false alarm)
        "false_negatives": fn,   # suspicious, but the method said normal (missed attack)
        "true_negatives": tn,    # normal, and the method said normal (correct)
        "precision": precision_score(labels, predictions, zero_division=0),
        "recall": recall_score(labels, predictions, zero_division=0),
    }


def make_table(rows):
    """Turn {name: result} into a table with one row per name; counts are shown as whole numbers."""
    table = pd.DataFrame(rows).T
    table[COUNT_COLUMNS] = table[COUNT_COLUMNS].astype(int)
    return table.round(2)


def compare_contamination(table, values):
    """Run Isolation Forest with different contamination values and evaluate each one.

    Only used to discuss the trade-off - in real life you do not have the answer key.
    """
    rows = {}
    for value in values:
        model = IsolationForest(contamination=value, random_state=42)
        predictions = (model.fit_predict(table[FEATURE_COLUMNS]) == -1).astype(int)
        rows[f"contamination={value}"] = evaluate(table["label"], predictions)
    return make_table(rows)


def main():
    table = pd.read_csv("data/results.csv", index_col="ip")

    results = make_table({method: evaluate(table["label"], table[method]) for method in METHODS})
    results.to_csv("data/validation.csv")
    print("Isolation Forest vs. simple rule:\n")
    print(results)

    print("\nIsolation Forest with different contamination values:\n")
    print(compare_contamination(table, ["auto", 0.05, 0.1, 0.15]))


if __name__ == "__main__":
    main()
