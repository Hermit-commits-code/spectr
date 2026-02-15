from ghost.checker import check_reputation, check_velocity


def test_inflated_trust_attack():
    # Scenario: 50,000 downloads but only 1 day old
    fake_data = {
        "info": {"downloads": {"last_month": 50000}},
        "releases": {"1.0.0": [{"upload_time": "2026-02-14T12:00:00"}]},
    }
    # This should return False (Flagging the risk)
    assert check_reputation("evil-package", fake_data) == False


def test_high_velocity_attack():
    # Scenario: 20 versions released in 2 days
    fake_releases = {
        f"0.0.{i}": [{"upload_time": "2026-02-14T00:00:00"}] for i in range(20)
    }
    fake_data = {"releases": fake_releases}

    # This should return False (Flagging the high release count)
    assert check_velocity(fake_data) == False
