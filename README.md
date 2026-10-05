# mreg [![Build Status](https://github.com/unioslo/mreg/actions/workflows/test.yml/badge.svg)](https://github.com/unioslo/mreg/actions/workflows/test.yml) [![Container Status](https://github.com/unioslo/mreg/actions/workflows/container-image.yml/badge.svg)](https://github.com/unioslo/mreg/actions/workflows/container-image.yml) [![Coverage Status](https://coveralls.io/repos/github/unioslo/mreg/badge.svg?branch=master)](https://coveralls.io/github/unioslo/mreg?branch=master)
mreg is an API (intended to be as RESTful as possible) for managing DNS.

An associated project for a command line interface using the mreg API is available at:
[mreg-cli](https://github.com/unioslo/mreg-cli/)

## Getting Started

### Prerequisites

The default Docker image and Python 3.14+ installations use Django 6.1, which requires PostgreSQL 15 or newer.

If you want to set up your own PostgreSQL server by installing the necessary packages manually, you might need to install dependencies for setting up the citext extension. On Fedora, the package is called [`postgresql-contrib`](https://packages.fedoraproject.org/pkgs/postgresql/postgresql-contrib/).

### Installing

#### Using Docker

Pre-built Docker images are available from [`ghcr.io/unioslo/mreg`](https://ghcr.io/unioslo/mreg):

```bash
docker pull ghcr.io/unioslo/mreg
```

You can also build locally, from the source:

```bash
docker build -t mreg .
```

It is expected that you mount a custom "mregsite" directory on /app/mregsite:

```bash
docker run \
  --mount type=bind,source=$HOME/customsettings,destination=/app/mregsite,readonly \
  ghcr.io/unioslo/mreg:latest
```

To access application logs outside the container, also mount `/app/logs`.

It is also possible to not mount a settings directory, and to supply database login details in environment variables instead, overriding the default values found in `mregsite/settings.py`.

```bash
docker run --network host \
  -e MREG_DB_HOST=my_postgres_host -e MREG_DB_NAME=mreg -e MREG_DB_USER=mreg -e MREG_DB_PASSWORD=mreg \
  ghcr.io/unioslo/mreg:latest
```

For a full example, see `docker-compose.yml`.

#### Manually

> [!TIP]
> Depending on your operating system, you may need to install additional packages to get the necessary dependencies for the project. At the very least you will probably require development packages for Python 3.

##### A step by step

Start by cloning the project from github. You need a terminal and the [uv](https://docs.astral.sh/uv/) package manager.

> [!IMPORTANT]  
> mreg relies on PEP 735 dependency groups for development, which is [not supported by pip](https://github.com/pypa/pip/issues/12963) as of version 24.3.1.

When you've got your copy of the mreg directory, set up the venv and install the dependencies:

```bash
uv sync --frozen
```

<details>
  <summary>Activate the venv (optional)</summary>

Optionally, you can also activate the created virtual environment. However, we will use `uv run` to run the commands in the virtual environment in this guide, which foregoes the need to activate the environment.

```bash
. .venv/bin/activate
```

Activating the venv allows you to run the commands with `python` instead of `uv run`.
</details>

Perform database migrations:

```bash
uv run manage.py migrate
```

Load sample data from fixtures into the now migrated database:

```bash
uv run manage.py loaddata mreg/fixtures/fixtures.json
```

And finally, run the server:

```bash
uv run manage.py runserver
```

You should now be able to open up a browser and go to http://localhost:8000/hosts/ and see
a list of hosts provided by the sample data. Or, you could perform a GET request to see
the returned data.

```bash
curl -X GET http://localhost:8000/hosts/
```

```json
[{"name":"ns1.uio.no"},{"name":"ns2.uio.no"},{"name":"lucario.uio.no"},{"name":"stewie.uio.no"},{"name":"vepsebol.uio.no"}]
```

## Running the tests

To run the tests for the system, simply run

```bash
uv run manage.py test
```

For **faster test execution**, you can run tests in parallel:

```bash
# Auto-detect number of CPUs
uv run manage.py test --parallel

# Or specify the number of processes
uv run manage.py test --parallel=4
```

This will significantly reduce test execution time (from 10-12 minutes to 2-4 minutes typically). Django creates separate test databases for each parallel process, and tests still use transaction rollback for isolation. Tox runs the tests in parallel mode by default.

**Running with coverage:**

```bash
# Run tests with coverage
coverage run --concurrency=multiprocessing manage.py test --parallel
coverage combine
coverage report -m
```

The `coverage combine` step is required to merge coverage data from all parallel processes.

### Updating test snapshots

Some tests may generate snapshot files that need to be updated when the expected output changes. Snapshot tests are currently run via pytest (and are automatically executed with `tox`). If snapshot tests fail, you can update the snapshots interactively by running:

```bash
uv run pytest --inline-snapshot=review
```

Or to just update all snapshots without reviewing:

```bash
uv run pytest --inline-snapshot=fix
```

New snapshots can be created via:

```bash
uv run pytest --inline-snapshot=create
```

## Environment Variables

mreg supports configuration via environment variables with the `MREG_` prefix. These can be used to override default settings without modifying `settings.py` or creating a `local_settings.py` file. This is especially useful when running mreg in containers or deployment environments. The applications supports reading from a dotenv file (`.env`) to set environment variables. The path to the dotenv file can be overridden by setting the `MREG_DOTENV_PATH` environment variable.

By default, the dotenv file is expected to be located at the project root with the name `.env`.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `MREG_DOTENV_PATH` | `.env` | Path to the dotenv file.|
| `MREG_DOTENV_OVERRIDE` | `False` | Override existing environment variables with values from the dotenv file. Makes the .env file the authoritative source for environment variables.|

### Django Core Configuration

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `MREG_SECRET_KEY` | Bundled development key | Django secret key. Must be set to a unique value in production. |
| `MREG_DEBUG` | `True` if `CI` is set, else `False` | Django DEBUG mode. Never enable in production. |
| `MREG_ALLOWED_HOSTS` | `127.0.0.1,localhost` | Comma-separated list of hosts the instance may serve. Ignored when DEBUG is `True`. |
| `MREG_SECURE_PROXY_SSL_HEADER` | unset | `header,value` pair to trust from the reverse proxy, e.g. `HTTP_X_FORWARDED_PROTO,https`. Left unset by default due to the [security implications](https://docs.djangoproject.com/en/stable/ref/settings/#secure-proxy-ssl-header). |
| `MREG_LANGUAGE_CODE` | `en-us` | Django language code. |
| `MREG_TIME_ZONE` | `Europe/Oslo` | Time zone (IANA name). |
| `MREG_USE_I18N` | `True` | Enable Django translation. |
| `MREG_USE_TZ` | `True` | Store datetimes as UTC. |
| `MREG_STATIC_URL` | `/static/` | URL prefix for static files. |
| `MREG_STATIC_ROOT` | `static/` | Directory for collected static files, relative to `BASE_DIR` (absolute paths win). |


### Database Configuration

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `MREG_DB_ENGINE` | `django.db.backends.postgresql` | Django database backend |
| `MREG_DB_NAME` | `mreg` | Database name |
| `MREG_DB_USER` | `mreg` | Database username |
| `MREG_DB_PASSWORD` | `""` | Database password |
| `MREG_DB_HOST` | `localhost` | Database host |
| `MREG_DB_PORT` | `5432` | Database port |
| `MREG_DB_CONN_MAX_AGE` | `0` | Persistent database connection lifetime in seconds (`0` closes the connection after each request) |

### Database Connection Pooling (psycopg3)

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `MREG_DB_POOL_ENABLED` | `True` | Enable or disable database connection pooling |
| `MREG_DB_POOL_MIN_SIZE` | `5` | Minimum idle connections in pool |
| `MREG_DB_POOL_MAX_SIZE` | `25` | Maximum connections in pool |
| `MREG_DB_POOL_MAX_IDLE` | `300` | Max idle time before closing (seconds) |
| `MREG_DB_POOL_MAX_LIFETIME` | `3600` | Max connection lifetime (seconds) |
| `MREG_DB_PSYCOPG_CONNECT_TIMEOUT` | `5` | Connection timeout (seconds) |
| `MREG_DB_PSYCOPG_OPTIONS` | `-c statement_timeout=30000` | PostgreSQL connection options |

### Logging Configuration

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `MREG_LOG_LEVEL` | `CRITICAL` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `MREG_LOG_FILE_NAME` | `logs/app.log` | Log file path |
| `MREG_LOG_FILE_SIZE` | `52428800` | Max log file size in bytes (50 MB) |
| `MREG_LOG_FILE_COUNT` | `10` | Number of log files to keep |
| `MREG_LOGGING_MAX_BODY_LENGTH` | `3000` | Max request/response body length to log |
| `MREG_REQUESTS_THRESHOLD_SLOW` | `1000` | Slow request threshold (ms) |
| `MREG_REQUESTS_LOG_LEVEL_SLOW` | `WARNING` | Log level for slow requests |
| `MREG_REQUESTS_THRESHOLD_VERY_SLOW` | `5000` | Very slow request threshold (ms) |
| `MREG_REQUESTS_LOG_LEVEL_VERY_SLOW` | `CRITICAL` | Log level for very slow requests |
| `MREG_LOG_CONSOLE_ENABLED` | `True` | Log to the console (stderr) in addition to the log file |

### Network Policy Configuration

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `MREG_NO_PROTECTED_POLICY_ATTRIBUTES` | `False` | Disable all protected policy attributes |
| `MREG_PROTECTED_POLICY_ATTRIBUTES` | `""` | key=value comma separated list of protected policy attributes, overrides defaults |
| `MREG_REQUIRED_POLICY_ATTRIBUTES` | `""` | comma separated list of required policy attributes |
| `MREG_MAX_COMMUNITES_PER_NETWORK` | `20` | Maximum communities per network |
| `MREG_MAP_GLOBAL_COMMUNITY_NAMES` | `False` | Enable global community name mapping |
| `MREG_GLOBAL_COMMUNITY_TEMPLATE_PATTERN` | `community` | Template pattern for community names |
| `MREG_COMMUNITY_TEMPLATE_PATTERN_ALLOWED_REGEX` | `^[a-zA-Z0-9_]+$` | Allowed regex for community patterns |
| `MREG_COMMUNITY_TEMPLATE_PATTERN_MAX_LENGTH` | `100` | Max length for community patterns |
| `MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY` | `True` | Require MAC address for an IP to be added to a community |
| `MREG_REQUIRE_VLAN_FOR_NETWORK_TO_HAVE_COMMUNITY` | `False` | Require VLAN to be set for a network for it to have communities |

### LDAP Configuration

Variables for `django-auth-ldap`. The variables that default to *unset* are only
passed to django-auth-ldap when they are actually set, since the library treats
an unset setting differently from an empty one.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `MREG_AUTH_LDAP_SERVER_URI` | `ldap://ldap.example.com` | LDAP server URI. |
| `MREG_AUTH_LDAP_USER_DN_TEMPLATE` | `uid=%(user)s,ou=users,dc=example,dc=com` | DN template used to look up users. |
| `MREG_AUTH_LDAP_START_TLS` | `True` | Negotiate TLS with the LDAP server. |
| `MREG_AUTH_LDAP_CACHE_TIMEOUT` | `3600` | Cache timeout in seconds for LDAP lookups. |
| `MREG_AUTH_LDAP_BIND_DN` | `""` | DN of the service account used for searches. |
| `MREG_AUTH_LDAP_BIND_PASSWORD` | `""` | Password of the bind service account. |
| `MREG_AUTH_LDAP_BIND_AS_AUTHENTICATING_USER` | `False` | Bind as the authenticating user instead of a service account. |
| `MREG_AUTH_LDAP_ALWAYS_UPDATE_USER` | `True` | Update the Django user from LDAP on every login. |
| `MREG_AUTH_LDAP_USER_ATTR_MAP` | `""` | Comma-separated `django_field=ldap_attribute` pairs, e.g. `first_name=givenName,last_name=sn`. |
| `MREG_AUTH_LDAP_MIRROR_GROUPS` | unset | Comma-separated list of LDAP group names to mirror to Django groups. Unset means mirror all groups. |
| `MREG_AUTH_LDAP_GLOBAL_OPTIONS` | unset | Comma-separated `OPTION=VALUE` pairs of global LDAP options, e.g. `OPT_X_TLS_REQUIRE_CERT=OPT_X_TLS_NEVER`. Names are resolved from the `ldap` module, values may also be plain integers. |
| `MREG_AUTH_LDAP_GROUP_TYPE` | unset | Group type class from `django_auth_ldap.config`, e.g. `NestedActiveDirectoryGroupType`. |
| `MREG_AUTH_LDAP_GROUP_SEARCH_BASE_DN` | unset | Base DN of the LDAP group search. Setting this variable enables the group search. |
| `MREG_AUTH_LDAP_GROUP_SEARCH_SCOPE` | `SUBTREE` | Group search scope: `SUBTREE`, `ONELEVEL` or `BASE`. Requires the base DN to be set. |
| `MREG_AUTH_LDAP_GROUP_SEARCH_FILTER` | `(objectClass=group)` | LDAP filter of the group search. Requires the base DN to be set. |
| `MREG_LDAP_GROUP_ATTR` | `memberof` | LDAP attribute on users holding their group memberships. |
| `MREG_LDAP_GROUP_RE` | `^cn=(?P<group_name>[\w\-]+),cn=netgroups,` | Regexp matched against group DNs; must contain the named group `group_name`. |

### Permission Groups

Group names used by mreg's permission system. The `default-*` names are
placeholders for tests and CI; production deployments should set these
variables to the real group names.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `MREG_SUPERUSER_GROUP` | `default-super-group` | Members get full access to everything. |
| `MREG_ADMINUSER_GROUP` | `default-admin-group` | Members get a high level of overall control. |
| `MREG_GROUPADMINUSER_GROUP` | `default-groupadmin-group` | Members may administer hostgroups. |
| `MREG_NETWORK_ADMIN_GROUP` | `default-networkadmin-group` | Members may administer networks. |
| `MREG_HOSTPOLICYADMIN_GROUP` | `default-hostpolicyadmin-group` | Members may administer hostpolicy roles and atoms. |
| `MREG_DNS_WILDCARD_GROUP` | `default-dns-wildcard-group` | Members may create wildcard DNS records. |
| `MREG_DNS_UNDERSCORE_GROUP` | `default-dns-underscore-group` | Members may create DNS records with underscores. |

### DNS Configuration

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `MREG_TXT_AUTO_RECORDS` | `example.org=v=spf1 -all` | TXT records automatically added to hosts in the listed zones. Entries are on the form `zone=record1,record2`, separated by `;`, e.g. `uio.no=v=spf1 -all`. An unset or empty variable falls back to the default. |

### MQ Event Publishing (RabbitMQ)

MQ event publishing is enabled only when `MREG_MQ_HOST` and the other required
variables (`MREG_MQ_EXCHANGE`, `MREG_MQ_USERNAME`, `MREG_MQ_PASSWORD`) are all
set. If `MREG_MQ_HOST` is set but a required variable is missing, mreg refuses
to start. Without `MREG_MQ_HOST`, no events are published.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `MREG_MQ_HOST` | unset | RabbitMQ host. Enables MQ event publishing when set together with the other required variables. |
| `MREG_MQ_SSL` | `False` | Use TLS for the RabbitMQ connection. |
| `MREG_MQ_VIRTUAL_HOST` | `/` | RabbitMQ virtual host. |
| `MREG_MQ_EXCHANGE` | unset (required) | Exchange to publish events to. |
| `MREG_MQ_DECLARE` | `False` | Declare the exchange (as a topic exchange) on connect. |
| `MREG_MQ_USERNAME` | unset (required) | RabbitMQ username. |
| `MREG_MQ_PASSWORD` | unset (required) | RabbitMQ password. |

### Sentry Error Tracking

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `MREG_SENTRY_DSN` | unset | Sentry DSN. When set, Sentry is initialized with the Django integration. |

### Django Configuration for VS Code

Running tests via the VS Code test runner (or other methods that otherwise bypass `manage.py`) requires setting the `MANAGE_PY_PATH` environment variable to point to the `manage.py` file of the Django project. `DJANGO_SETTINGS_MODULE` is also available to override for specific local needs.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `DJANGO_SETTINGS_MODULE` | `""` | Django settings module. Required when not running via `manage.py`|
| `MANAGE_PY_PATH` | `""` | Path to the `manage.py` file of the Django project. Required when running via VS Code test runner or other methods that bypass `manage.py`|

Copy the bundled `.env.example` file to `.env` to make VS Code automatically source the default settings module.

```bash
cp .env.example .env
```

### Example Environment Variables Usage With Docker

```bash
# Using environment variables with Docker
docker run --network host \
  -e MREG_DB_HOST=my_postgres_host \
  -e MREG_DB_NAME=mreg \
  -e MREG_DB_USER=mreg \
  -e MREG_DB_PASSWORD=secretpassword \
  -e MREG_LOG_LEVEL=INFO \
  -e MREG_DB_POOL_MAX_SIZE=50 \
  ghcr.io/unioslo/mreg:latest
```

## Local Settings

The application supports setting the aforementioned settings persistently via a `.env` file.

### `.env`

To override entries in `mregsite/settings.py`, create a file `.env` or rename `.env.example` to `.env`.

Example `.env` file:

```bash
DJANGO_SETTINGS_MODULE=mregsite.settings
MREG_DB_NAME=mreg_sample
MREG_DB_USER=mreg_user
MREG_DB_PASSWORD=mregdbpass
MREG_DB_HOST=localhost
MREG_DB_PORT=5432
```

The default database setup in `settings.py` uses Django's postgres connection pool, but if you want to disable pooling for local development, you can set `MREG_DB_POOL_ENABLED` to `0` or `false` in `.env`:

```bash
MREG_DB_POOL_ENABLED=0 # or false
```

### `local_settings.py` (deprecated)

> [!WARNING]
> `local_settings.py` is deprecated. Prefer using a `.env` file for local configuration. `local_settings.py` allows arbitrary Python code, which can lead to security and maintainability issues.

To override entries in `mregsite/settings.py`, create a file `mregsite/local_settings.py` and add the entries there.

```python
MREG_DB_NAME = "mreg_sample"
MREG_DB_USER = "mreg_user"
MREG_DB_PASSWORD = "mregdbpass"
MREG_DB_HOST = "localhost"
MREG_DB_PORT = "5432"
```


The default database setup in `settings.py` uses Django's postgres connection pool, but if you want to disable pooling for local development, you can set `MREG_DB_POOL_ENABLED` to `False` in `local_settings.py`:

```python
MREG_DB_POOL_ENABLED = False
```

## Profiling

mreg supports request and query profiling via [django-silk](https://github.com/jazzband/django-silk). Silk is an optional dependency in the `profile` dependency group (and also a part of the `dev` dependency group, thus is installed automatically in development environments). When enabled, Silk provides detailed insights into request performance, including SQL query analysis and optionally cProfile-based profiling of Python code.

When enabled, Silk results are accessible in the web interface at http://127.0.0.1:8000/silk/ by default.

### Enabling profiling

Silk is included in the `dev` dependency group and is available automatically after `uv sync`. For deployments that need it without the full dev group (e.g. a profiling-enabled container image), use `uv sync --only-group profile`.

Set `MREG_PROFILING_ENABLED=True` to activate Silk instrumentation. When enabled, Silk records every request and its associated SQL queries, which are viewable at `/silk/`.

> [!WARNING]
> Profiling adds overhead to every request. Only enable it in development or controlled environments, never in production.

### Profiling configuration

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `MREG_PROFILING_ENABLED` | `False` | Enable Silk request/query instrumentation |
| `MREG_SILKY_PYTHON_PROFILER` | `True` | Use cProfile for detailed per-request profiling (requires `MREG_PROFILING_ENABLED`) |
| `MREG_SILKY_PYTHON_PROFILER_BINARY` | `True` | Save cProfile results to disk as `.prof` files for offline analysis |
| `MREG_SILKY_PYTHON_PROFILER_RESULT_PATH` | `silk/profiles` | Directory to write `.prof` files into |
| `MREG_SILKY_META` | `False` | Enable Silk meta-profiling (measures Silk's own overhead) |

When `MREG_SILKY_PYTHON_PROFILER` is disabled, Silk still collects request/response data and timings, but not the detailed call-level profiling information.

The `.prof` files written to `MREG_SILKY_PYTHON_PROFILER_RESULT_PATH` are standard cProfile format and can be opened with tools like `snakeviz` or Python's `pstats` module, in addition to the Silk UI.


## Contributing

Patches and PRs are welcome. However, there are a number of intricacies in both code structure and internal
expectations, so you should probably get in touch with the project maintainers before you start working on
anything major. If in doubt, open an issue to start a discussion.

See [CONTRIBUTING.md](CONTRIBUTING.md) for more information.

## Reference material

* [NS, 1](http://help.dnsmadeeasy.com/managed-dns/dns-record-types/ns-record/)
* [NS, 2](https://www.digitalocean.com/community/questions/what-is-the-point-of-the-ns-records)
* [SOA](https://en.wikipedia.org/wiki/SOA_record)
* [A](https://en.wikipedia.org/wiki/List_of_DNS_record_types#A) / [AAAA](https://en.wikipedia.org/wiki/IPv6_address#Domain_Name_System)
* [CNAME](https://en.wikipedia.org/wiki/CNAME_record)
* [PTR](https://en.wikipedia.org/wiki/List_of_DNS_record_types#PTR)
* [HINFO](https://en.wikipedia.org/wiki/List_of_DNS_record_types#HINFO)
* [NAPTR](https://en.wikipedia.org/wiki/NAPTR_record)
* [SRV](https://en.wikipedia.org/wiki/SRV_record)
* [TXT](https://en.wikipedia.org/wiki/TXT_record)
* [LOC](https://en.wikipedia.org/wiki/LOC_record)
* [Other DNS record types](https://en.wikipedia.org/wiki/List_of_DNS_record_types)
* [Telephone number mapping/ENUM](https://en.wikipedia.org/wiki/Telephone_number_mapping)

## Authors

* **Øyvind Hagberg**
* **Øyvind Kolbu**
* **Paal Braathen**
* **Geir Ulvik**
* **Nils Hiorth**
* **Nicolay Mohebi**
* **Magnus Hirth**
* **Marius Bakke**
* **Safet Amedov**
* **Tannaz Roshandel**
* **Terje Kvernes**

## License

This project is licensed under the GPL-3.0 License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* [Django](https://www.djangoproject.com/)
* [Django Rest Framework](http://www.django-rest-framework.org/)
