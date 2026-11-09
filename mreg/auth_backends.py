"""Authentication backend paths shared by settings and runtime validation.

Must not import Django: mregsite/settings.py imports this module before Django is fully loaded.
"""

LEGACY_BACKENDS = ("django_auth_ldap.backend.LDAPBackend", "django.contrib.auth.backends.ModelBackend")
DIRECTORY_BACKENDS = ("mreg.directory_auth.LocalUserBackend", "mreg.directory_auth.LDAPPasswordBackend")
