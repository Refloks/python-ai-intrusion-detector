from generate_logs import night_logins


def test_night_logins_are_between_2_and_4():
    for time, text in night_logins():
        assert 2 <= time.hour < 4
        assert "Accepted password" in text
