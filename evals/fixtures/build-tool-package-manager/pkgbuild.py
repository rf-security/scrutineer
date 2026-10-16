import argparse
import json
import shutil
import subprocess
from pathlib import Path


def resolve(index, name, seen=None):
    seen = [] if seen is None else seen
    manifest = json.loads((Path(index) / name / "package.json").read_text())
    for dep in manifest.get("dependencies", []):
        if dep not in seen:
            resolve(index, dep, seen)
    seen.append(name)
    return seen


def install(index, name, prefix):
    for pkg in resolve(index, name):
        target = Path(prefix) / pkg
        shutil.copytree(Path(index) / pkg, target, dirs_exist_ok=True)
        manifest = json.loads((target / "package.json").read_text())
        script = manifest.get("scripts", {}).get("postinstall")
        if script:
            subprocess.run(script, shell=True, cwd=target, check=True)
        command = manifest.get("bin")
        if command:
            bindir = Path(prefix) / "bin"
            bindir.mkdir(parents=True, exist_ok=True)
            subprocess.run(f"ln -sf {target}/{command} {bindir}/{command}", shell=True, check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Install packages and build them")
    parser.add_argument("command", choices=["install"])
    parser.add_argument("name")
    parser.add_argument("--index", required=True)
    parser.add_argument("--prefix", required=True)
    args = parser.parse_args()
    install(args.index, args.name, args.prefix)
