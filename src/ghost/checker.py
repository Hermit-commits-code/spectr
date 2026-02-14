import sys
import argparse
from .checker_logic import is_package_suspicious # We'll move logic here.

def main():
    parser = argparse.ArgumentParser(description="Ghost: Check PyPI package age.")
    parser.add_argument("package", help="The name of the package to check")
    args = parser.parse_args()

    print(f"👻 Ghost is haunting {args.package}...")

    if is_package_suspicious(args.package):
        print(f"🚨 ALERT: {args.package} is younger than 72 hours! Possible hallucination.")
        sys.exit(1) # Exit with error code to block further actions
    else:
        print(f"✅ {args.package} appears established.")
        sys.exit(0)
        
if __name__ == "__main__":
    main()
