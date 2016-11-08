#!/bin/bash
set -e

echo "CONFIG API"

cd /app
python config.py

echo "START OAUTH"

if [ "$1" = "START" ]; then
    exec "/app/bin/gunicorn wsgi:app --bind 0.0.0.0:$PORT --worker-class aiohttp.worker.GunicornUVLoopWebWorker --workers $NUM_WORKERS --timeout 200"
else
    exec "$@"
fi