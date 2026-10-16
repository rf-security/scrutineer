# taskrun

A small task runner. `python -m taskrun.cli build` reads `taskrun.json` from
the workspace and runs the named task. Workspaces may ship plugins under
`.taskrun/plugins/` that register hooks around tasks. Build outputs are stored
in a content-addressed cache that `taskrun/cache.py` restores into the
workspace.

`example-app/` is a separate project in the same repository that only uses
taskrun for its own tests.
