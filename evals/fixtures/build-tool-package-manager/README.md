# pkgbuild

A minimal package installer and build driver. `python pkgbuild.py install NAME
--index DIR --prefix DIR` resolves NAME and its dependencies from a local
index of package manifests, copies each package into the prefix and runs the
`scripts.postinstall` command from the package manifest to build it. A package
that declares a `bin` command is linked into `PREFIX/bin` by a shell command
the installer builds from that manifest value.
