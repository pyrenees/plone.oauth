#!/bin/bash
set -e

echo "CONFIG API"

cd /plone
python config-oauth.py

echo "START OAUTH"

exec "$@"