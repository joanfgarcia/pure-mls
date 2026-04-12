#!/bin/bash
# scripts/publish.sh - Sovereign Publishing Protocol
# This script handles the build and upload process for pure-mls.

set -e

echo "--- 🛠️  Cleaning previous builds ---"
rm -rf dist/ build/ *.egg-info

echo "--- 📏 Running ruff lint & format check ---"
python3 -m ruff check .
python3 -m ruff format --check .

echo "--- 🏗️  Building package (uv) ---"
# Using python3 -m build as a fallback if uv is not in path locally
if command -v uv &> /dev/null; then
	uv build
else
	python3 -m build
fi

echo "--- 🚀 Uploading to PyPI ---"
# Note: Requires TWINE_USERNAME and TWINE_PASSWORD/TWINE_TOKEN env vars
# or manual entry during prompt.
python3 -m twine upload dist/*

echo "--- ✅ Published version $(grep 'version =' pyproject.toml | cut -d '"' -f 2) successfully! ---"
