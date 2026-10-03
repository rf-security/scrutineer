# Package launcher installer

Run `python install.py package.json --prefix /chosen/location` to install the
launchers declared by a package author. Packages use declarative JSON and may
only create launchers within the chosen prefix; installation runs no package
code or lifecycle hooks. The user selects the prefix and the package author
supplies the manifest, including the launcher names.
