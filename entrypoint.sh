#!/bin/sh
set -e
cd /app
uv run ./manage.py create_citext_extension
uv run ./manage.py migrate
#uv run ./manage.py runserver 0.0.0.0:8000

# pass signals on to the gunicorn process
function sigterm()
{
	echo "Received SIGTERM"
	kill -term `cat /var/run/gunicorn.pid`
}
trap sigterm SIGTERM

# doing it this way to be able to forward signals
uv run gunicorn --workers=3 --bind=0.0.0.0 mregsite.wsgi --pid /var/run/gunicorn.pid &
wait $!
