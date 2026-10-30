import pandas as pd

from model import run_isolation_forest, simple_rule


def make_table():
    """20 normal IPs that look alike, and one IP with many failed logins."""
    rows = {f"10.0.0.{n}": {"failed": n % 2, "accepted": 5, "night_logins": 0, "unique_users": 1}
            for n in range(20)}
    rows["203.0.113.5"] = {"failed": 50, "accepted": 0, "night_logins": 0, "unique_users": 5}
    return pd.DataFrame.from_dict(rows, orient="index")


def test_simple_rule_uses_limit():
    table = pd.DataFrame({"failed": [5, 6]}, index=["a", "b"])
    assert list(simple_rule(table)) == [0, 1]  # 5 is not "more than 5", 6 is


def test_isolation_forest_finds_obvious_attacker():
    table = make_table()
    result = pd.Series(run_isolation_forest(table), index=table.index)
    assert result["203.0.113.5"] == 1


def test_isolation_forest_returns_one_answer_per_ip():
    table = make_table()
    assert len(run_isolation_forest(table)) == len(table)
