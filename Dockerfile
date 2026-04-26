FROM python:3.12-slim

ARG UID=1000
ARG GID=1000
ARG CURRENT_USER=app
ARG CURRENT_GROUP=app
ARG APP_TIMEZONE=UTC
ARG DEBIAN_MIRROR_URL
ARG DEBIAN_SECURITY_MIRROR_URL
ARG PIP_INDEX_URL

ENV TZ=${APP_TIMEZONE}
ENV PYTHONUNBUFFERED=1
ENV PIP_INDEX_URL=${PIP_INDEX_URL}
ENV DEBIAN_SECURITY_MIRROR_URL=${DEBIAN_SECURITY_MIRROR_URL}

RUN if [ -n "$DEBIAN_MIRROR_URL" ]; then \
        if [ -z "$DEBIAN_SECURITY_MIRROR_URL" ]; then \
            DEBIAN_SECURITY_MIRROR_URL="$DEBIAN_MIRROR_URL"; \
        fi; \
        if [ -f /etc/apt/sources.list ]; then \
            sed -i "s|http://deb.debian.org/debian|$DEBIAN_MIRROR_URL|g" /etc/apt/sources.list && \
            sed -i "s|http://security.debian.org/debian-security|$DEBIAN_SECURITY_MIRROR_URL|g" /etc/apt/sources.list && \
            sed -i "s|http://mirror-linux.runflare.com/debian-security|$DEBIAN_SECURITY_MIRROR_URL|g" /etc/apt/sources.list && \
            sed -i "s|http://.*/debian-security|$DEBIAN_SECURITY_MIRROR_URL|g" /etc/apt/sources.list; \
        fi; \
        if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
            sed -i "s|http://deb.debian.org/debian|$DEBIAN_MIRROR_URL|g" /etc/apt/sources.list.d/debian.sources && \
            sed -i "s|http://security.debian.org/debian-security|$DEBIAN_SECURITY_MIRROR_URL|g" /etc/apt/sources.list.d/debian.sources && \
            sed -i "s|http://mirror-linux.runflare.com/debian-security|$DEBIAN_SECURITY_MIRROR_URL|g" /etc/apt/sources.list.d/debian.sources && \
            sed -i "s|http://.*/debian-security|$DEBIAN_SECURITY_MIRROR_URL|g" /etc/apt/sources.list.d/debian.sources; \
        fi; \
    fi && \
    apt-get update && apt-get install -y --no-install-recommends tzdata && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN groupadd -g "$GID" "${CURRENT_GROUP}" && \
    useradd -u "$UID" -g "${CURRENT_GROUP}" -m -s /bin/bash "${CURRENT_USER}"

WORKDIR /code

COPY pyproject.toml README.md ./
COPY gateway ./gateway

RUN pip install --no-cache-dir .

RUN mkdir -p /code/config /code/data /code/logs && \
    chown -R "${CURRENT_USER}:${CURRENT_GROUP}" /code

USER ${CURRENT_USER}

CMD ["python3", "-m", "gateway.main", "--host", "0.0.0.0", "--port", "8000", "--config", "config/services.yaml"]
