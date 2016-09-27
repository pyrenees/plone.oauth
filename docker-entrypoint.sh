#!/bin/bash
set -e

echo "CONFIG API"

cd /app
python config.py

echo "START OAUTH"

exec "$@"