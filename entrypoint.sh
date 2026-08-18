#!/bin/sh
set -eu

cd /app
python manage.py create_citext_extension
python manage.py migrate

# Configure multiprocess metrics only for the new Gunicorn process. Doing this
# after one-shot management commands prevents their metric files becoming stale.
PROMETHEUS_MULTIPROC_DIR="${PROMETHEUS_MULTIPROC_DIR:-/tmp/mreg-prometheus-multiproc}"
export PROMETHEUS_MULTIPROC_DIR
mkdir -p "$PROMETHEUS_MULTIPROC_DIR"
find "$PROMETHEUS_MULTIPROC_DIR" -maxdepth 1 -type f -name '*.db' -delete

# Let gunicorn become PID 1 so container stop signals are delivered directly.
exec gunicorn \
    --config /app/mregsite/gunicorn_conf.py \
    --workers 3 \
    --bind 0.0.0.0:8000 \
    --pid /var/run/gunicorn.pid \
    mregsite.wsgi
