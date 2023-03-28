#!/bin/sh
set -e
cd /app
./manage.py create_citext_extension --database template1
./manage.py test --noinput --failfast
