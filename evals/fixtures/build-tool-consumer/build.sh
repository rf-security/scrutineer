#!/bin/sh
set -eu
mkdir -p dist
cp app.py dist/app.py
tar -czf dist/notes.tar.gz -C dist app.py
