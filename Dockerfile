# syntax=docker/dockerfile:1

# hadolint ignore=DL3007
FROM python:3.11-slim AS builder

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    make wget gcc git npm libpam0g-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build UI components
RUN cd adminui/frontend && npm install && npm run build && \
    cd ../../internal/mfaportal/resources/frontend && npm install && npm run build

# Install Python dependencies and build the package
RUN pip install --no-cache-dir build && \
    python -m build && \
    pip install --no-cache-dir dist/*.whl

# hadolint ignore=DL3007
FROM python:3.11-slim

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    iptables iproute2 net-tools pam-auth-update libpam0g && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app/wag

# Copy installed Python package from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/wag /usr/local/bin/wag
COPY --chmod=0770 docker_entrypoint.sh /
COPY example_config.json /app/example_config.json

VOLUME /data
VOLUME /cfg

CMD ["/docker_entrypoint.sh"]
