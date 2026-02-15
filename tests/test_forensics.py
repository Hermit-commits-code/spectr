# Append to tests/test_forensics.py
import requests

from spectr.checker import check_for_updates, check_identity


def test_check_identity_flags_suspicious_email():
    # Brand-jacking attempt: 'google-auth' maintained by a generic gmail
    mock_data = {"info": {"author_email": "attacker@gmail.com"}}
    passed, meta = check_identity("google-auth", mock_data)
    assert passed is False
    assert "gmail.com" in meta["email"]


def test_check_identity_allows_official_email():
    # Legit: 'google-auth' maintained by google.com
    mock_data = {"info": {"author_email": "admin@google.com"}}
    passed, meta = check_identity("google-auth", mock_data)
    assert passed is True


def test_check_for_updates_handles_offline(mocker):
    # Simulate a connection timeout
    mocker.patch("requests.get", side_effect=requests.exceptions.ConnectTimeout)

    # This should not raise an exception
    try:
        check_for_updates("0.13.0")
    except Exception as e:
        pytest.fail(f"check_for_updates crashed on network error: {e}")


def test_whitelist_bypass(mocker):
    # 1. Mock the existence of the whitelist file
    mocker.patch("spectr.checker.os.path.exists", return_value=True)

    # 2. Setup dual-mode mocking for the open() call
    # This handles both "rb" (hashing) and "r" (reading names)
    bytes_data = mocker.mock_open(read_data=b"safe-pkg\n").return_value
    string_data = mocker.mock_open(read_data="safe-pkg\n").return_value

    def open_side_effect(file, mode="r", **kwargs):
        if "b" in mode:
            return bytes_data
        return string_data

    mocker.patch("spectr.checker.open", side_effect=open_side_effect)

    # 3. Simulate command line: spectr check safe-pkg
    mocker.patch("sys.argv", ["spectr", "check", "safe-pkg"])

    # 4. Mock the network and the signature verification
    mock_get = mocker.patch("spectr.checker.requests.get")
    mocker.patch("spectr.checker.verify_whitelist_integrity", return_value=True)

    # 5. Execute main and catch the exit
    try:
        from spectr.checker import main

        main()
    except SystemExit:
        pass

    # 6. Refined Assertions
    # We extract all URLs that requests.get was called with
    urls_called = [call.args[0] for call in mock_get.call_args_list]

    # PROOF: The forensic check for 'safe-pkg' was never attempted
    assert "https://pypi.org/pypi/safe-pkg/json" not in urls_called

    # CONFIRMATION: The update check for 'spectr' still happened
    assert "https://pypi.org/pypi/spectr/json" in urls_called
