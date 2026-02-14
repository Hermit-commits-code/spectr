from datetime import datetime, timezone
import requests

def is_package_suspicious(package_name: str, age_threshold_hours: int = 72) -> bool:
    """
    Check if a PyPI package is younger than the specified age threshold.

    Args:
        package_name (str): The name of the package to check.
        age_threshold_hours (int): The age threshold in hours (default is 72).

    Returns:
        bool: True if the package is suspicious (younger than threshold), False otherwise.
    """
    url = f"https://pypi.org/pypi/{package_name}/json"

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 404:
            # Not found on PyPI = impossible to install, so not 'suspicious' yet
            return False

        data = response.json()

        # Get the first release's upload time
        releases = data.get("releases", {})
        if not releases:
            return False

        first_version = list(releases.keys())[0]
        upload_time_str = releases[first_version][0]["upload_time"]

        upload_time = datetime.fromisoformat(upload_time_str).replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)

        age_in_hours = (now - upload_time).total_seconds() / 3600

        return age_in_hours < age_threshold_hours

    except Exception:
        return False
