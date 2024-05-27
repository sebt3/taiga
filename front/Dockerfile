FROM docker.io/node:18-slim as builder
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /plugins
RUN set -eux; \
    apt-get update; \
    apt-get install -y ca-certificates git; \
    git clone --depth 1 https://github.com/taigaio/taiga-contrib-oidc-auth.git .; \
    cd front; npm install; ./node_modules/.bin/gulp build

FROM docker.io/nginx:1.23-alpine
COPY default.conf /etc/nginx/conf.d/default.conf
COPY config_env_subst.sh /docker-entrypoint.d/30_config_env_subst.sh
COPY .tags /tmp/

RUN set -eux; \
    apk update; \
    apk add --no-cache --virtual .build-deps \
       subversion; \
    apk add \
       bash; \
    # Install taiga-front core
    wget "https://github.com/taigaio/taiga-front-dist/archive/$(sed 's/,.*//' /tmp/.tags).zip" -O source.zip; \
    unzip source.zip; \
    rm source.zip; \
    mv "/taiga-front-dist-$(sed 's/,.*//' /tmp/.tags)" /taiga; \
    chmod +x /docker-entrypoint.d/30_config_env_subst.sh; \
    # Install taiga-front contribs
    mkdir /taiga/dist/plugins; \
    cd /taiga/dist/plugins; \
    # Slack
    wget "https://github.com/taigaio/taiga-contrib-slack/archive/$(sed 's/.*,//' /tmp/.tags).0.zip" -O source.zip; \
    unzip -j source.zip "taiga-contrib-slack-$(sed 's/.*,//' /tmp/.tags).0/front/dist/*" -d slack; \
    rm source.zip; \
    # Github
    wget "http://github.com/taigaio/taiga-contrib-github-auth/archive/$(sed 's/.*,//' /tmp/.tags).0.zip" -O source.zip; \
    unzip -j source.zip "taiga-contrib-github-auth-$(sed 's/.*,//' /tmp/.tags).0/front/dist/*" -d github-auth; \
    rm source.zip; \
    # Gitlab
    wget "http://github.com/taigaio/taiga-contrib-gitlab-auth/archive/$(sed 's/.*,//' /tmp/.tags).0.zip" -O source.zip; \
    unzip -j source.zip "taiga-contrib-gitlab-auth-$(sed 's/.*,//' /tmp/.tags).0/front/dist/*" -d gitlab-auth; \
    rm source.zip; \
    # Remove unused dependencies
    apk del --no-cache .build-deps; \
    # Ready for nginx
    mv /taiga/dist/* /usr/share/nginx/html; \
    rm -rf /taiga

COPY --from=builder /plugins/front/dist/ /usr/share/nginx/html/plugins/oidc-auth/
COPY conf.json.template /usr/share/nginx/html/
