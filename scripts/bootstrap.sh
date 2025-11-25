#!/usr/bin/env bash
set -e

if git config --get core.hooksPath > /dev/null; then
  echo "Hooks ya instalados previamente"
  exit 0
fi

git config core.hooksPath .githooks
chmod +x .githooks/* 2>/dev/null || true

echo "Hooks configurados en .githooks/"