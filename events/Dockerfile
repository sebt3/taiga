FROM node:16-alpine
LABEL maintainer="support@taiga.io"
WORKDIR /taiga-events
COPY .tags /tmp/
COPY entrypoint.sh /usr/local/bin
RUN set -eux; \
    apk update; \
    apk add --no-cache gettext su-exec git ca-certificates openssh-client; \
    git clone --depth 1 --branch "$(sed 's/,.*//' /tmp/.tags)" https://github.com/taigaio/taiga-events.git .; \
    npm install; \
    chmod +x docker/entrypoint.sh "/usr/local/bin/entrypoint.sh"; \
    addgroup -g 99 -S taiga; \
    adduser -u 99 -S -D -G taiga -H -h /taiga-events -s /bin/sh taiga; \
    chown -R taiga:taiga /taiga-events

EXPOSE 8888
USER taiga
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
