import pandas as pd

from model import run_isolation_forest, simple_rule

NORMAL = {"failed": 0, "accepted": 5, "night_logins": 0, "unique_users": 1, "blocked": 0, "unique_ports": 0}


def make_table():
    """20 normal IPs that look alike, one brute-force attacker and one port scanner."""
    rows = {f"10.0.0.{n}": {**NORMAL, "failed": n % 2} for n in range(20)}   # {**NORMAL, ...} = copy and change
    rows["203.0.113.5"] = {**NORMAL, "failed": 50, "accepted": 0, "unique_users": 5}
    rows["192.0.2.50"] = {**NORMAL, "accepted": 0, "blocked": 500, "unique_ports": 500}
    return pd.DataFrame.from_dict(rows, orient="index")


def test_simple_rule_uses_limits():
    table = pd.DataFrame({"failed": [5, 6, 0, 0], "unique_ports": [0, 0, 10, 11]}, index=["a", "b", "c", "d"])
    # 5 failed is not "more than 5", 6 is.  10 ports is not "more than 10", 11 is.
    assert list(simple_rule(table)) == [0, 1, 0, 1]


def test_isolation_forest_finds_obvious_attackers():
    table = make_table()
    result = pd.Series(run_isolation_forest(table), index=table.index)
    assert result["203.0.113.5"] == 1
    assert result["192.0.2.50"] == 1


def test_isolation_forest_returns_one_answer_per_ip():
    table = make_table()
    assert len(run_isolation_forest(table)) == len(table)
