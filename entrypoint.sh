#!/bin/sh
set -e
cd /app
./manage.py create_citext_extension
./manage.py migrate
#./manage.py runserver 0.0.0.0:8000

# pass signals on to the gunicorn process
function sigterm()
{
	echo "Received SIGTERM"
	kill -term `cat /var/run/gunicorn.pid`
}
trap sigterm SIGTERM

# doing it this way to be able to forward signals
/usr/bin/gunicorn --workers=3 --bind=0.0.0.0 mregsite.wsgi --pid /var/run/gunicorn.pid &
wait $!
