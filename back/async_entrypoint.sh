#!/usr/bin/env bash
set -euo pipefail
for file in $(ls /docker-entrypoint.d/*.sh 2>/dev/null||:);do
    echo "loading $file";
    . $file;
done
echo Starting Celery...
exec celery -A taiga.celery worker -B \
    --concurrency 4 \
    -l INFO \
    "$@"
