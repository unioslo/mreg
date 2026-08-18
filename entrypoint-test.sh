#!/bin/sh
set -eu

cd /app
python manage.py create_citext_extension --database template1
python manage.py test --noinput --failfast --parallel
