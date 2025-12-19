# mreg [![Build Status](https://github.com/unioslo/mreg/actions/workflows/test.yml/badge.svg)](https://github.com/unioslo/mreg/actions/workflows/test.yml) [![Container Status](https://github.com/unioslo/mreg/actions/workflows/container-image.yml/badge.svg)](https://github.com/unioslo/mreg/actions/workflows/container-image.yml) [![Coverage Status](https://coveralls.io/repos/github/unioslo/mreg/badge.svg?branch=master)](https://coveralls.io/github/unioslo/mreg?branch=master)
mreg is an API (intended to be as RESTful as possible) for managing DNS.

An associated project for a command line interface using the mreg API is available at:
[mreg-cli](https://github.com/unioslo/mreg-cli/)

## Getting Started

### Prerequisites

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

This will significantly reduce test execution time (from 10-12 minutes to 2-4 minutes typically). Django creates separate test databases for each parallel process, and tests still use transaction rollback for isolation.

**Running with coverage:**

```bash
# Run tests with coverage
coverage run --concurrency=multiprocessing manage.py test --parallel
coverage combine
coverage report -m
```

The `coverage combine` step is required to merge coverage data from all parallel processes.

## Local Settings

To override entries in `mregsite/settings.py`, create a file `mregsite/local_settings.py` and add the entries there.
For example, the default database setup in `settings.py` uses sqlite3, but if you set up your postgres database
you'll want to override this when testing. To to this, just add the following to your `local_settings.py` file:

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'mreg_sample',
        'USER': 'mreg_user',
        'PASSWORD': 'mregdbpass',
        'HOST': 'localhost',
    }
}
```

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
