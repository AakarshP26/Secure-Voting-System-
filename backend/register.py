"""
register.py — Register a user in the secure chat database.

Usage:
    python backend/register.py --user alice --password secret
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import db
import auth


def main() -> None:
    parser = argparse.ArgumentParser(description="Register a chat user")
    parser.add_argument("--user",     required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args()

    db.start()

    ok, err = auth.register_user(args.user, args.password)
    if ok:
        print(f"[OK] User '{args.user}' registered successfully.")
    else:
        print(f"[ERROR] {err}", file=sys.stderr)
        sys.exit(1)

    db.stop()


if __name__ == "__main__":
    main()
