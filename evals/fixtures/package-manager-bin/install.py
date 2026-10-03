import argparse
import json
from pathlib import Path


def install_package(manifest_path, prefix):
    manifest = json.loads(Path(manifest_path).read_text())
    bin_dir = Path(prefix) / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name in manifest.get("bin", []):
        destination = bin_dir / name
        destination.write_text("#!/bin/sh\nexit 0\n")
        destination.chmod(0o755)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Install package launchers")
    parser.add_argument("manifest")
    parser.add_argument("--prefix", required=True)
    args = parser.parse_args()
    install_package(args.manifest, args.prefix)
