#!/usr/bin/env bash
# Publish Voyege to your GitHub. Run from the repo root on your own machine.
set -euo pipefail
REPO="${1:-voyege}"            # repo name (default: voyege)
VIS="${2:-public}"            # public | private
cd "$(dirname "$0")"

command -v gh >/dev/null || { echo "Install GitHub CLI first: https://cli.github.com"; exit 1; }
gh auth status >/dev/null 2>&1 || gh auth login

gh repo create "$REPO" --"$VIS" --source=. --remote=origin --push
echo "Published → $(gh repo view "$REPO" --json url -q .url)"
