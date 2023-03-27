#!/bin/sh
set -e
cd /app
./manage.py test --noinput --failfast
