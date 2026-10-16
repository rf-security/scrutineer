import json
import subprocess
import sys
from pathlib import Path

from taskrun.plugins import load_plugins


def run_task(workspace, name):
    """Run a task from the workspace task file after its plugin hooks."""
    tasks = json.loads((Path(workspace) / "taskrun.json").read_text())["tasks"]
    hooks = load_plugins(workspace)
    if "before" in hooks:
        hooks["before"](name)
    return subprocess.run(tasks[name]["run"], cwd=workspace, check=False).returncode


if __name__ == "__main__":
    sys.exit(run_task(Path.cwd(), sys.argv[1]))
