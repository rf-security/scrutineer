import importlib.util
from pathlib import Path


def load_plugins(workspace):
    """Import every plugin the workspace ships so its hooks are registered."""
    hooks = {}
    for path in sorted((Path(workspace) / ".taskrun" / "plugins").glob("*.py")):
        spec = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        hooks.update(getattr(module, "HOOKS", {}))
    return hooks
