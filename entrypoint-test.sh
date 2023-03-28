#!/bin/sh
set -e
cd /app
./manage.py create_citext_extension
./manage.py test --noinput --failfast
