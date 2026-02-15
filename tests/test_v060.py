from spectr.checker import check_reputation, check_velocity


def test_inflated_trust_attack():
    status, meta = check_reputation(
        "evil-package",
        {
            "info": {"downloads": {"last_month": 50000}},
            "releases": {"1.0.0": [{"upload_time": "2026-02-14T12:00:00"}]},
        },
    )
    assert status is False
    assert meta["downloads"] == 50000


def test_high_velocity_attack():
    # We provide a dictionary where each version points to a list of file info
    # This matches the structure expected by: for file_info in releases[version]
    mock_data = {
        "releases": {
            f"0.0.{i}": [{"upload_time": "2026-02-14T00:00:00Z"}] for i in range(20)
        }
    }
    status, meta = check_velocity(mock_data)
    assert status is False
    assert meta["releases"] == 20
