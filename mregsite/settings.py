"""
Django settings for mreg project.

Generated by 'django-admin startproject' using Django 2.0.6.

For more information on this file, see
https://docs.djangoproject.com/en/2.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.0/ref/settings/
"""

import os
import sys

TESTING = len(sys.argv) > 1 and sys.argv[1] == 'test'

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = ')e#67040xjxar=zl^y#@#b*zilv2dxtraj582$^(e6!wf++_n#'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = []

AUTH_USER_MODEL = 'mreg.User'

AUTHENTICATION_BACKENDS = (
    'django_auth_ldap.backend.LDAPBackend',
    'django.contrib.auth.backends.ModelBackend',
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
    'django_logging',
    'netfields',
    'mreg',
    'hostpolicy',
]

MIDDLEWARE = [
    'django_logging.middleware.DjangoLoggingMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'mregsite.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'mregsite.wsgi.application'


# Database
# https://docs.djangoproject.com/en/2.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'mydatabase',
    }
}

if 'TRAVIS' in os.environ:
    DEBUG = True
    ALLOWED_HOSTS = ["127.0.0.1", "localhost"]
    DATABASES = {
        'default': {
            'ENGINE':   'django.db.backends.postgresql',
            'NAME':     'travisci',
            'USER':     'postgres',
            'PASSWORD': '',
            'HOST':     'localhost',
            'PORT':     '5433',
        }
    }

# Password validation
# https://docs.djangoproject.com/en/2.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Europe/Oslo'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.0/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static/')

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'mreg.authentication.ExpiringTokenAuthentication',
    ),
    'DEFAULT_PAGINATION_CLASS':
        'mreg.api.v1.pagination.StandardResultsSetPagination',
    'DEFAULT_PERMISSION_CLASSES': (
        'mreg.api.permissions.IsAuthenticatedAndReadOnly',
    ),
    'DEFAULT_SCHEMA_CLASS': 'rest_framework.schemas.openapi.AutoSchema',
}

# This setting must be defined for mreg.api.permissions.IsInRequiredGroup
# to work.
# REQUIRED_USER_GROUPS = "default-required-group"

REST_FRAMEWORK_EXTENSIONS = {
    'DEFAULT_OBJECT_ETAG_FUNC':
        'rest_framework_extensions.utils.default_object_etag_func',
    'DEFAULT_LIST_ETAG_FUNC':
        'rest_framework_extensions.utils.default_list_etag_func',
}

# Django logging settings. To enable the default django request/response logging for API in stdout,
# add "DISABLE_EXISTING_LOGGERS" = False
DJANGO_LOGGING = {
    "CONSOLE_LOG": False,
    'IGNORED_PATHS': ['/admin', '/static', '/favicon.ico', '/api/token-auth']
}
SQL_LOG = False

# TXT record(s) automatically added to a host when added to a ForwardZone.
TXT_AUTO_RECORDS = {
        'example.org': ('v=spf1 -all', ),
}

# Import local settings that may override those in this file.
try:
    from .local_settings import *  # noqa: F401,F403
except ImportError:
    pass

if TESTING:
    SUPERUSER_GROUP = "default-super-group"
    ADMINUSER_GROUP = "default-admin-group"
    GROUPADMINUSER_GROUP = "default-groupadmin-group"
    NETWORK_ADMIN_GROUP = "default-networkadmin-group"
    HOSTPOLICYADMIN_GROUP = "default-hostpolicyadmin-group"
