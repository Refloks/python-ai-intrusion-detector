from validate import evaluate


def test_perfect_predictions():
    result = evaluate([0, 0, 1, 1], [0, 0, 1, 1])
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0


def test_one_false_alarm_and_one_missed_attack():
    # labels:      normal, normal, attack, attack
    # predictions: alarm,  normal, attack, normal
    result = evaluate([0, 0, 1, 1], [1, 0, 1, 0])
    assert result["false_positives"] == 1
    assert result["false_negatives"] == 1
    assert result["precision"] == 0.5  # 1 of 2 alarms was a real attack
    assert result["recall"] == 0.5     # 1 of 2 attacks was found


def test_no_alarms_gives_zero_instead_of_error():
    result = evaluate([0, 1], [0, 0])
    assert result["precision"] == 0
    assert result["recall"] == 0
