#!/bin/sh
set -e

if [ "${1#-}" != "${1}" ] || [ -z "$(command -v "${1}")" ]; then
  set -- node "$@"
fi

if [ -z "$TAIGA_EVENTS_RABBITMQ_HOST" ]; then
  echo "TAIGA_EVENTS_RABBITMQ_HOST is not set. Using default value: taiga-events-rabbitmq"
  export TAIGA_EVENTS_RABBITMQ_HOST=taiga-events-rabbitmq
fi

envsubst < /taiga-events/docker/env.template \
         > /taiga-events/.env

# Start node process
echo Starting Taiga events
exec npm run start:production
