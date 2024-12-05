"""
Django settings for mreg project.

Generated by 'django-admin startproject' using Django 2.0.6.

For more information on this file, see
https://docs.djangoproject.com/en/2.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.0/ref/settings/
"""

import logging.config
import os
import sys

import structlog

import mreg.log_processors

TESTING = len(sys.argv) > 1 and sys.argv[1] == "test"

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = ")e#67040xjxar=zl^y#@#b*zilv2dxtraj582$^(e6!wf++_n#"

LOG_LEVEL = os.environ.get("MREG_LOG_LEVEL", "CRITICAL").upper()

REQUESTS_THRESHOLD_SLOW = 1000
REQUESTS_LOG_LEVEL_SLOW = "WARNING"

REQUESTS_THRESHOLD_VERY_SLOW = 5000
REQUESTS_LOG_LEVEL_VERY_SLOW = "CRITICAL"

LOGGING_MAX_BODY_LENGTH = 3000

LOG_FILE_SIZE = os.environ.get("MREG_LOG_FILE_SIZE", 50 * 1024 * 1024)
LOG_FILE_COUNT = os.environ.get("MREG_LOG_FILE_COUNT", 10)
LOG_FILE_NAME = os.path.join(
    BASE_DIR, os.environ.get("MREG_LOG_FILE_NAME", "logs/app.log")
)

# If the log directory doesn't exist, create it.
log_dir = os.path.dirname(LOG_FILE_NAME)
if not os.path.exists(log_dir): # pragma: no cover
    try: # pragma: no cover
        os.makedirs(log_dir)
    except OSError as e:
        print(f"Failed to create log directory {log_dir}: {e}")
        sys.exit(1)

# Check if the log file and directory is writable.
if not os.access(log_dir, os.W_OK): # pragma: no cover
    print(f"Log directory {log_dir} is not writable")
    sys.exit(1)

# Check if LOG_FILE_NAME exists and if it is writable.
if os.path.exists(LOG_FILE_NAME) and not os.access(LOG_FILE_NAME, os.W_OK):
    print(f"Log file {LOG_FILE_NAME} is not writable")
    sys.exit(1)

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True if "CI" in os.environ else False

# The IP addresses that can access this instance.  Ignored if DEBUG
# is True.
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

AUTH_USER_MODEL = "mreg.User"

AUTHENTICATION_BACKENDS = (
    "django_auth_ldap.backend.LDAPBackend",
    "django.contrib.auth.backends.ModelBackend",
)

AUTH_LDAP_SERVER_URI = "ldap://ldap.example.com"
AUTH_LDAP_USER_DN_TEMPLATE = "uid=%(user)s,ou=users,dc=example,dc=com"
AUTH_LDAP_START_TLS = True
AUTH_LDAP_CACHE_TIMEOUT = 3600

# Used by signals.py populate_user_from_ldap to match attributes
# via a regexp to groups, which are added to the logged in user.
LDAP_GROUP_ATTR = "memberof"
# LDAP_GROUP_RE must include a named group with name "group_name".
LDAP_GROUP_RE = r"""^cn=(?P<group_name>[\w\-]+),cn=netgroups,"""

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework.authtoken',
    'django_filters',
    'netfields',
    'mreg',
    'hostpolicy',
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "mreg.middleware.logging_http.LoggingMiddleware",
]

ROOT_URLCONF = "mregsite.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "mregsite.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("MREG_DB_NAME", "mreg"),
        "USER": os.environ.get("MREG_DB_USER", "mreg"),
        "PASSWORD": os.environ.get("MREG_DB_PASSWORD", ""),
        "HOST": os.environ.get("MREG_DB_HOST", "localhost"),
        "PORT": os.environ.get("MREG_DB_PORT", "5432"),
    }
}


# Password validation
# https://docs.djangoproject.com/en/2.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.0/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "Europe/Oslo"

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.0/howto/static-files/

STATIC_URL = "/static/"
STATIC_ROOT = os.path.join(BASE_DIR, "static/")


# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"


REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "mreg.authentication.ExpiringTokenAuthentication",
    ),
    'DEFAULT_FILTER_BACKENDS': (
        'django_filters.rest_framework.DjangoFilterBackend',
    ),
    'DEFAULT_PAGINATION_CLASS':
        'mreg.api.v1.pagination.StandardResultsSetPagination',
    'DEFAULT_PERMISSION_CLASSES': (
        'mreg.api.permissions.IsAuthenticatedAndReadOnly',
    ),
    'DEFAULT_SCHEMA_CLASS': 'rest_framework.schemas.openapi.AutoSchema',
}

REST_FRAMEWORK_EXTENSIONS = {
    "DEFAULT_OBJECT_ETAG_FUNC": "rest_framework_extensions.utils.default_object_etag_func",
    "DEFAULT_LIST_ETAG_FUNC": "rest_framework_extensions.utils.default_list_etag_func",
}

# TXT record(s) automatically added to a host when added to a ForwardZone.
TXT_AUTO_RECORDS = {
    "example.org": ("v=spf1 -all",),
}

# Example of how MQ settings would look (put yours in local_settings.py)
# MQ_CONFIG = {
#    "host": "...",
#    "ssl": True/False,
#    "virtual_host": "...",
#    "exchange": "...",
#    "declare": True/False,
#    "username": "...",
#    "password": "...",
# }

timestamper = structlog.processors.TimeStamper(fmt="iso")
# The pre_chain setup here allows us to add support for loggers that aren't
# using structlog and wrap them semi-nicely into something mostly readable.
# Disabled for now, but kept here for reference.
# pre_chain = [
#    structlog.stdlib.add_log_level,
#    structlog.stdlib.ExtraAdder(),
#    timestamper,
# ]

if TESTING or DEBUG:
    console_processors = [
        mreg.log_processors.collapse_request_id_processor,
        mreg.log_processors.reorder_keys_processor,
        mreg.log_processors.RequestColorTracker(),
        structlog.stdlib.ProcessorFormatter.remove_processors_meta,
        structlog.dev.ConsoleRenderer(colors=True, sort_keys=False),
    ]
else: # pragma: no cover
    console_processors = [
        structlog.stdlib.ProcessorFormatter.remove_processors_meta,
        structlog.processors.JSONRenderer(),
    ]


logging.config.dictConfig(
    {
        "version": 1,
        "disable_existing_loggers": True,
        "formatters": {
            "plain": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processors": [
                    structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    structlog.processors.JSONRenderer(),
                ],
                #                "foreign_pre_chain": pre_chain,
            },
            "colored": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processors": console_processors,
                #                "foreign_pre_chain": pre_chain,
            },
        },
        "handlers": {
            "default": {
                "level": LOG_LEVEL,
                "class": "logging.StreamHandler",
                "formatter": "colored",
            },
            "file": {
                "level": LOG_LEVEL,
                "class": "logging.handlers.RotatingFileHandler",
                "maxBytes": LOG_FILE_SIZE,
                "backupCount": LOG_FILE_COUNT,
                "filename": LOG_FILE_NAME,
                "formatter": "plain",
            },
        },
        "loggers": {
            "": {
                "handlers": ["default", "file"],
                "level": "DEBUG",
                "propagate": True,
            },
        },
    }
)
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        mreg.log_processors.filter_sensitive_data,
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.CallsiteParameterAdder(
            {
                structlog.processors.CallsiteParameter.FILENAME,
                structlog.processors.CallsiteParameter.FUNC_NAME,
                structlog.processors.CallsiteParameter.LINENO,
            }
        ),
        timestamper,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

# Import local settings that may override those in this file.
try:
    from .local_settings import *  # noqa: F401,F403
except ImportError:
    pass

if TESTING or "CI" in os.environ:
    SUPERUSER_GROUP = "default-super-group"
    ADMINUSER_GROUP = "default-admin-group"
    GROUPADMINUSER_GROUP = "default-groupadmin-group"
    NETWORK_ADMIN_GROUP = "default-networkadmin-group"
    HOSTPOLICYADMIN_GROUP = "default-hostpolicyadmin-group"
    DNS_WILDCARD_GROUP = "default-dns-wildcard-group"
    DNS_UNDERSCORE_GROUP = "default-dns-underscore-group"
