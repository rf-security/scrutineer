import hashlib
from pathlib import Path


def restore_entry(dest, name, data, expected_sha256):
    """Restore one cached output file into the workspace.

    The digest comes from the local build graph, not from the cache entry.
    """
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        return False
    root = Path(dest).resolve()
    target = (root / name).resolve()
    if not target.is_relative_to(root):
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return True
