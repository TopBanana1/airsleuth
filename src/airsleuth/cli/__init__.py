from __future__ import annotations
import sys

def main(argv=None):
    # Allow: `python -m airsleuth` (no args) -> help
    if argv is None:
        argv = sys.argv[1:]

    if not argv or argv[0] in ("-h", "--help"):
        print("airsleuth: subcommands\n  profile   Build/merge Wi-Fi manifest JSON from capture(s)")
        return 0

    cmd, *rest = argv
    if cmd == "profile":
        from .profile import main as profile_main
        return profile_main(rest)

    print(f"Unknown subcommand: {cmd}")
    return 2
