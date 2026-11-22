#!/usr/bin/env python3
"""Fetch source dependencies for a standalone checkout.

Each dependency is the antinuous mirror at the commit research pins, named
in deps.json, so this repository's CI tests what research builds. It is
fetched into a gitignored directory (.deps/<name> here; grpc-mojo uses
packages/<name>) so include paths keep working.

Already-present directories are left untouched, so a local clone wins over
a fresh fetch. Use --update to check out previously fetched clones at
their pinned commit.

URL selection: $GIT_URL_TEMPLATE (default
"https://github.com/antinuous/{name}.git").
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TEMPLATE = "https://github.com/antinuous/{name}.git"


def checkout(dest: Path, url: str, commit: str) -> None:
    """A shallow fetch of one commit by its id, which GitHub serves."""
    if not dest.exists():
        subprocess.run(["git", "init", "-q", str(dest)], check=True)
        subprocess.run(["git", "-C", str(dest), "remote", "add", "origin", url], check=True)
    subprocess.run(
        ["git", "-C", str(dest), "fetch", "-q", "--depth", "1", "origin", commit],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(dest), "checkout", "-q", "--detach", "FETCH_HEAD"],
        check=True,
    )


def main() -> int:
    manifest = ROOT / "deps.json"
    if not manifest.exists():
        print("no deps.json: nothing to fetch")
        return 0
    spec = json.loads(manifest.read_text())
    template = os.environ.get("GIT_URL_TEMPLATE", DEFAULT_TEMPLATE)
    update = "--update" in sys.argv[1:]
    dest_root = ROOT / spec.get("dir", "packages")
    dest_root.mkdir(exist_ok=True)

    for name, dep in spec["deps"].items():
        dest = dest_root / name
        commit = dep["commit"]
        if dest.exists() and not update:
            print(f"  {name}: already present at {dest} (skipped)")
            continue
        url = dep.get("url") or template.format(name=name)
        print(f"  {name}: {url} @ {commit}")
        checkout(dest, url, commit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
