#!/bin/sh
set -e
cd /app
uv run ./manage.py create_citext_extension --database template1
uv run ./manage.py test --noinput --failfast --parallel
