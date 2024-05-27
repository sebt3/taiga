#!/usr/bin/env bash
set -euo pipefail
for file in $(ls /docker-entrypoint.d/*.sh 2>/dev/null||:);do
    echo "loading $file";
    . $file;
done
echo Starting Taiga Protected
exec gunicorn server:app \
    --name taiga_protected \
    --bind 0.0.0.0:8003 \
    --workers 4 \
    --worker-tmp-dir /dev/shm \
    --max-requests 3600 \
    --max-requests-jitter 360 \
    --timeout 60 \
    --log-level=info \
    --access-logfile - \
    "$@"
