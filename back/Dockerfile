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
       wget unzip curl; \
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
    pip install --no-cache-dir taiga-contrib-ldap-auth-ext; \
    cp /taiga-back/docker/config.py /taiga-back/settings/; \
    python manage.py compilemessages; \
    python manage.py collectstatic --no-input; \
    curl -L -o /tmp/taiga-contrib-openid-auth.zip "https://github.com/robrotheram/taiga-contrib-openid-auth/archive/master.zip"; \
    mkdir -p /tmp/taiga-contrib-openid-auth; \
    unzip /tmp/taiga-contrib-openid-auth.zip -d /tmp/; \
    python -m pip install /tmp/taiga-contrib-openid-auth-master/back; \
    rm -rf /tmp/taiga-contrib-openid-auth; \
    git clone --depth 1 https://github.com/taigaio/taiga-contrib-oidc-auth.git /tmp/taiga-contrib-oidc-auth; \
    python -m pip install /tmp/taiga-contrib-oidc-auth/back install; \
    rm -rf /tmp/taiga-contrib-oidc-auth; \
    mv /tmp/config.py /tmp/urls.py /taiga-back/settings/; \
    chmod +x /usr/local/bin/entrypoint.sh; \
    chmod +x /usr/local/bin/async_entrypoint.sh; \
    #  create taiga group and user to use it and give permissions over the code (in entrypoint)
    groupadd --system taiga --gid=999; \
    useradd --system --gid taiga --uid=999 --shell=/bin/bash taiga; \
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
       wget curl unzip; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/* /root/.cache requirements.txt requirements-contribs.txt; \
    find . -name '__pycache__' -exec rm -r '{}' +; \
    find . -name '*pyc' -exec rm -r '{}' +; \
    find . -name '*po' -exec rm -r '{}' +

ENV DJANGO_SETTINGS_MODULE=settings.config
ENV ENABLE_SLACK=False \
    ENABLE_GITLAB_AUTH=False \
    GITLAB_URL=https://gitlab.com \
    GITLAB_API_CLIENT_ID= \
    GITLAB_API_CLIENT_SECRET= \
    ENABLE_GITHUB_AUTH=False \
    GITHUB_API_CLIENT_ID= \
    GITHUB_API_CLIENT_SECRET= \
    ENABLE_LDAP=False \
    LDAP_START_TLS=False \
    LDAP_SERVER= \
    LDAP_PORT=389 \
    LDAP_BIND_DN= \
    LDAP_BIND_PASSWORD= \
    LDAP_SEARCH_BASE= \
    LDAP_USERNAME_ATTRIBUTE=uid \
    LDAP_EMAIL_ATTRIBUTE=mail \
    LDAP_FULL_NAME_ATTRIBUTE=cn \
    LDAP_SAVE_LOGIN_PASSWORD=True \
    LDAP_FALLBACK=normal \
    ENABLE_OPENID=False \
    OPENID_USER_URL= \
    OPENID_TOKEN_URL= \
    OPENID_CLIENT_ID= \
    OPENID_CLIENT_SECRET= \
    OPENID_SCOPE="openid email"

USER taiga
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
