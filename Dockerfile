FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Vendor security release: the distribution package currently lags these fixes.
# Explicit amd64 package; fail rather than silently use an older native parser.
ADD --checksum=sha256:d3ee9e401974855a1edc1761b1425417d126de618d5f0c91cd51209f69f6fcc2 https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.4.6/clamav-1.4.6.linux.x86_64.deb /tmp/clamav.deb
RUN test "$(dpkg --print-architecture)" = amd64 \
    && dpkg-deb -x /tmp/clamav.deb / \
    && ldconfig && clamscan --version \
    && rm /tmp/clamav.deb \
    && mkdir -p /var/lib/clamav
COPY deployment/freshclam.conf /usr/local/etc/freshclam.conf
ENV CLAMAV_DATABASE_DIR=/var/lib/clamav

WORKDIR /app
COPY requirements.txt ./
RUN python -m pip install --upgrade pip && python -m pip install -r requirements.txt
COPY . .
RUN mkdir -p /data/appora/uploads && chown -R 10001:10001 /app /data/appora

USER 10001:10001
EXPOSE 8000
CMD ["gunicorn", "--workers", "4", "--worker-class", "gevent", "--worker-connections", "1200", "--keep-alive", "5", "--timeout", "300", "--bind", "0.0.0.0:8000", "--access-logfile", "-", "--access-logformat", "%(h)s %(m)s %(s)s %(L)s", "--error-logfile", "-", "app:app"]
