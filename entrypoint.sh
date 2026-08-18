#!/bin/sh
set -eu

cd /app
python manage.py create_citext_extension
python manage.py migrate

# Let gunicorn become PID 1 so container stop signals are delivered directly.
exec gunicorn --workers 3 --bind 0.0.0.0:8000 mregsite.wsgi
