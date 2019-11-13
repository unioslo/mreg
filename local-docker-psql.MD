First install dockerimage and expose the port to localhost:
```
docker run -p 127.0.0.1:5432:5432 --name postgres -e POSTGRES_PASSWORD=secret -d postgres
```

Then add a mreg user and db:
```
psql -h localhost -U postgres template1 << EOF
CREATE EXTENSION citext;
CREATE DATABASE mreg;
CREATE USER mreg WITH ENCRYPTED PASSWORD 'mregpass';
GRANT ALL PRIVILEGES ON DATABASE mreg to mreg;
EOF
```

If testing with postgresql, grant the mreg user the right to create databases for testing:
```
psql -h localhost -U postgres << EOF
ALTER USER mreg CREATEDB;
EOF
```

Finally add settings to django::
```
cat >> mregsite/local_settings.py << EOF
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'mreg',
        'USER': 'mreg',
        'PASSWORD': 'mregpass',
        'HOST': 'localhost',
    }
}
EOF
```
