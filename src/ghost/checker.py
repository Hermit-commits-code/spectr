import argparse
import os
import sys
from datetime import datetime, timezone

import requests

from ghost.similarity import check_for_typosquatting

WHITELIST_FILE = ".ghost-whitelist"

# --- HELPER FUNCTIONS ---


def ensure_whitelist_exists():
    """Ensures the whitelist file exists to prevent FileNotFoundError."""
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "w") as f:
            f.write(
                "# Ghost Whitelist - Add trusted package names here (one per line)\n"
            )
        print(f"📦 Created default {WHITELIST_FILE}")


def is_whitelisted(package_name):
    """Checks if a package is in the local trust list."""
    if not os.path.exists(WHITELIST_FILE):
        return False
    with open(WHITELIST_FILE, "r") as file:
        # Strip whitespace and ignore comments
        whitelisted = [
            line.strip() for line in file.readlines() if not line.startswith("#")
        ]
        return package_name in whitelisted


def fetch_pypi_data(package_name):
    """Single entry point for PyPI data to avoid redundant API calls."""
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.json()
        return None
    except requests.RequestException:
        return None


# --- SECURITY ENGINES ---


def check_velocity(data):
    """v0.6.0: Checks if a package is pushing too many versions too fast (Bot behavior)."""
    releases = data.get("releases", {})
    if not releases:
        return True

    upload_times = []
    for version in releases:
        for file_info in releases[version]:
            upload_times.append(
                datetime.fromisoformat(file_info["upload_time"].replace("Z", ""))
            )

    if not upload_times:
        return True

    first_upload = min(upload_times)
    days_old = (
        datetime.now(timezone.utc).replace(tzinfo=None) - first_upload
    ).days or 1

    # Flag if > 15 releases in less than 3 days (Classic spray-and-pray attack)
    if days_old < 3 and len(releases) > 15:
        print(
            f"⚠️  CAUTION: Unusual release velocity ({len(releases)} versions in {days_old} days)."
        )
        return False
    return True


def check_reputation(package_name, data):
    """v0.6.0: Flags 'Too good to be true' scenarios (50k downloads on a 1-day old package)."""
    info = data.get("info", {})
    # Note: PyPI stats are often 0 in JSON, but we check if provided
    downloads = info.get("downloads", {}).get("last_month", 0)

    releases = data.get("releases", {})
    upload_times = [
        datetime.fromisoformat(r[0].get("upload_time").replace("Z", ""))
        for r in releases.values()
        if r
    ]

    if not upload_times:
        return True

    days_old = (
        datetime.now(timezone.utc).replace(tzinfo=None) - min(upload_times)
    ).days or 1
    # High downloads + Very young = Suspected Bot Inflation
    if downloads > 10000 and days_old < 3:
        print(
            f"🚩 WARNING: {package_name} has high download counts but is only {days_old} days old!"
        )
        return False
    return True


def is_package_suspicious(data):
    """v0.3.0: Basic Age Check (The 72-hour rule)."""
    releases = data.get("releases", {})
    if not releases:
        return True

    upload_times = [
        datetime.fromisoformat(r[0].get("upload_time").replace("Z", ""))
        for r in releases.values()
        if r
    ]

    first_upload = min(upload_times)
    hours_old = (datetime.utcnow() - first_upload).total_seconds() / 3600

    if hours_old < 72:
        return True
    return False


# --- MAIN EXECUTION ---


def main():
    ensure_whitelist_exists()

    parser = argparse.ArgumentParser(description="Ghost: Supply Chain Defense Tool")
    parser.add_argument("package", help="The name of the package to check")
    args = parser.parse_args()

    print(f"👻 Ghost is haunting {args.package}...")

    # 1. Check Whitelist First (Express Lane)
    if is_whitelisted(args.package):
        print(f"⚪ {args.package} is whitelisted. Skipping security checks.")
        sys.exit(0)

    # 2. Typosquatting Check (Local Logic)
    if check_for_typosquatting(args.package):
        print(f"🚨 ALERT: Suspected typosquatting for '{args.package}'.")
        sys.exit(1)

    # 3. Fetch Remote Data Once
    data = fetch_pypi_data(args.package)
    if not data:
        print(f"❓ Could not find {args.package} on PyPI. Proceed with caution.")
        sys.exit(0)

    # 4. Age Check
    if is_package_suspicious(data):
        print(f"🚨 ALERT: {args.package} is younger than 72 hours!")
        sys.exit(1)

    # 5. Reputation & Velocity Checks (v0.6.0)
    if not check_reputation(args.package, data) or not check_velocity(data):
        print("🛑 SECURITY RISK: Metadata suggests automated trust inflation.")
        sys.exit(1)

    print(f"✅ {args.package} appears established and safe.")
    sys.exit(0)


if __name__ == "__main__":
    main()
