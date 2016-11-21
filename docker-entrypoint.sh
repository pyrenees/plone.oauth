#!/bin/bash
set -e

echo "CONFIG API"

cd /app
python config.py
echo "Contents of 'config.py' file:"
cat config.json

echo "START OAUTH"
echo "info: COMMAND is < $1 >"
echo "properties: [port= $PORT, num_workers=$NUM_WORKERS]"

if [ "$1" = "START" ]; then
    echo "Waiting 30 seconds for Redis and LDAP to be up..."
    sleep 30
    exec /app/bin/gunicorn wsgi:app --bind 0.0.0.0:$PORT --worker-class aiohttp.worker.GunicornUVLoopWebWorker --workers $NUM_WORKERS --timeout 200
elif [ "$1" = "DEBUG" ]; then
    exec /bin/sleep 10000
elif [ "$1" = "TEST" ]; then
    echo "Waiting 30 seconds for Redis and LDAP to be up..."
    sleep 30
    /app/bin/py.test --ldap ldap --ldap-port 10389 --redis redis --redis-port 6379
else
    exec "$@"
fi
