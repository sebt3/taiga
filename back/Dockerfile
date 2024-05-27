FROM docker.io/python:3.11-slim
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONFAULTHANDLER=1
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /taiga-back
ENV GOSU_VERSION 1.12
COPY .tags config.py urls.py /tmp/
COPY async_entrypoint.sh entrypoint.sh /usr/local/bin

RUN set -eux; \
    apt-get update; \
    apt-get install -y \
       build-essential \
       ca-certificates \
       gettext \
       libpq5 \
       libpq-dev \
       git \
       net-tools \
       procps \
       wget; \
    mkdir -p /docker-entrypoint.d; \
    git clone --depth 1 --branch "$(sed 's/,.*//' /tmp/.tags)" https://github.com/taigaio/taiga-back.git .; \
    # install gosu
    dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')"; \
    wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch"; \
	wget -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch.asc"; \
    chmod +x /usr/local/bin/gosu; \
    # verify gosu signature
    export GNUPGHOME="$(mktemp -d)"; \
	gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4; \
	gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu; \
	command -v gpgconf && gpgconf --kill all || :; \
	rm -rf "$GNUPGHOME" /usr/local/bin/gosu.asc; \
    # install Taiga dependencies
    python -m pip install --upgrade pip; \
    python -m pip install wheel; \
    python -m pip install -r requirements.txt; \
    python -m pip install -r requirements-contribs.txt; \
    cp /taiga-back/docker/config.py /taiga-back/settings/; \
    python manage.py compilemessages; \
    python manage.py collectstatic --no-input; \
    git clone --depth 1 https://github.com/taigaio/taiga-contrib-oidc-auth.git /tmp/taiga-contrib-oidc-auth; \
    python -m pip install -e /tmp/taiga-contrib-oidc-auth/back install; rm -rf /tmp/taiga-contrib-oidc-auth; \
    mv /tmp/config.py /tmp/urls.py /taiga-back/settings/; \
    chmod +x /usr/local/bin/entrypoint.sh; \
    chmod +x /usr/local/bin/async_entrypoint.sh; \
    #  create taiga group and user to use it and give permissions over the code (in entrypoint)
    groupadd --system taiga --gid=999; \
    useradd --system --no-create-home --gid taiga --uid=999 --shell=/bin/bash taiga; \
    mkdir -p /taiga-back/media/exports; \
    chown -R taiga:taiga /taiga-back; \
    # remove unneeded files and packages
    apt-get purge -y \
       build-essential \
       gettext \
       git \
       libpq-dev \
       net-tools \
       procps \
       wget; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/* /root/.cache requirements.txt requirements-contribs.txt; \
    find . -name '__pycache__' -exec rm -r '{}' +; \
    find . -name '*pyc' -exec rm -r '{}' +; \
    find . -name '*po' -exec rm -r '{}' +

ENV DJANGO_SETTINGS_MODULE=settings.config
USER taiga
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
