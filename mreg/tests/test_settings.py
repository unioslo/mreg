import contextlib
import importlib
import os
import sys
import tempfile
from types import ModuleType
from unittest.mock import patch

from django.test import SimpleTestCase

import mregsite.settings as app_settings
from mreg.env import (
    envvar,
    envvar_list,
    envvar_pairs,
    make_ldap_group_type,
    make_ldap_search,
    parse_header_pair,
    parse_ldap_options,
    parse_protected_policy_attrs,
    parse_txt_auto_records,
)


@contextlib.contextmanager
def reload_settings(env: dict[str, str] | None = None, drop: tuple[str, ...] = ()):
    """Reload mregsite.settings with specific environment variables set.

    Restores the original environment and reloads the settings module again
    afterwards, so tests do not leak environment variables or settings.

    Args:
        env: Environment variables to set during the reload, on top of the
            current environment.
        drop: Names of conditionally defined settings module attributes to
            remove before each reload, as attributes otherwise survive
            reloads of the module.

    Yields:
        The reloaded settings module.
    """
    env_backup = dict(os.environ)
    try:
        if env:
            os.environ.update(env)
        for attr in drop:
            if hasattr(app_settings, attr):
                delattr(app_settings, attr)
        yield importlib.reload(app_settings)
    finally:
        os.environ.clear()
        os.environ.update(env_backup)
        for attr in drop:
            if hasattr(app_settings, attr):
                delattr(app_settings, attr)
        importlib.reload(app_settings)


class SettingsTestCase(SimpleTestCase):
    """This class defines the test suite for settings.py."""

    def test_get_pool_settings_enabled(self):
        with patch.object(app_settings, "MREG_DB_POOL_ENABLED", True):
            result = app_settings.get_pool_settings()
        assert isinstance(result, dict)
        assert "max_size" in result

    def test_get_pool_settings_disabled(self):
        with patch.object(app_settings, "MREG_DB_POOL_ENABLED", False):
            result = app_settings.get_pool_settings()
        assert result is False


class SettingsHelpersTests(SimpleTestCase):
    def test_envvar_bool_and_casting(self):
        os.environ["MREG_TEST_BOOL"] = "original"
        original = os.environ.get("MREG_TEST_BOOL")
        try:
            os.environ["MREG_TEST_BOOL"] = "true"
            self.assertTrue(envvar("MREG_TEST_BOOL", False))

            os.environ["MREG_TEST_BOOL"] = "false"
            self.assertFalse(envvar("MREG_TEST_BOOL", True))

            os.environ["MREG_TEST_BOOL"] = "maybe"
            self.assertTrue(envvar("MREG_TEST_BOOL", True))
        finally:
            if original is None:
                os.environ.pop("MREG_TEST_BOOL", None)  # pragma: no cover
            else:
                os.environ["MREG_TEST_BOOL"] = original

        os.environ["MREG_TEST_INT"] = "original"
        original_int = os.environ.get("MREG_TEST_INT")
        try:
            os.environ["MREG_TEST_INT"] = "not-an-int"
            self.assertEqual(envvar("MREG_TEST_INT", 5), 5)
        finally:
            if original_int is None:
                os.environ.pop("MREG_TEST_INT", None)  # pragma: no cover
            else:
                os.environ["MREG_TEST_INT"] = original_int

    def test_parse_protected_attrs(self):
        result = parse_protected_policy_attrs(" ,=ignored,foo=,bar=baz ")
        self.assertEqual(
            result,
            [
                {"name": "foo", "description": "Protected attribute foo."},
                {"name": "bar", "description": "baz"},
            ],
        )


class EnvvarListAndPairsTests(SimpleTestCase):
    def test_envvar_list_unset_returns_default(self):
        self.assertEqual(envvar_list("MREG_TEST_LIST_UNSET", ["a", "b"]), ["a", "b"])

    def test_envvar_list_parses_comma_separated(self):
        os.environ["MREG_TEST_LIST"] = " x , y ,, z "
        original = os.environ.get("MREG_TEST_LIST")
        try:
            self.assertEqual(envvar_list("MREG_TEST_LIST", []), ["x", "y", "z"])
        finally:
            if original is None:
                os.environ.pop("MREG_TEST_LIST", None)  # pragma: no cover
            else:
                os.environ["MREG_TEST_LIST"] = original

    def test_envvar_pairs_unset_returns_default(self):
        self.assertEqual(envvar_pairs("MREG_TEST_PAIRS_UNSET", {"a": "b"}), {"a": "b"})

    def test_envvar_pairs_parses_and_skips_malformed(self):
        os.environ["MREG_TEST_PAIRS"] = "first_name=givenName,last_name=sn,broken,=x,"
        original = os.environ.get("MREG_TEST_PAIRS")
        try:
            self.assertEqual(
                envvar_pairs("MREG_TEST_PAIRS", {}),
                {"first_name": "givenName", "last_name": "sn"},
            )
        finally:
            if original is None:
                os.environ.pop("MREG_TEST_PAIRS", None)  # pragma: no cover
            else:
                os.environ["MREG_TEST_PAIRS"] = original


class EnvParserTests(SimpleTestCase):
    def test_parse_txt_auto_records(self):
        self.assertEqual(
            parse_txt_auto_records("uio.no=v=spf1 -all; example.org=a, b ;"),
            {"uio.no": ("v=spf1 -all",), "example.org": ("a", "b")},
        )

    def test_parse_header_pair(self):
        self.assertEqual(
            parse_header_pair("HTTP_X_FORWARDED_PROTO, https"),
            ("HTTP_X_FORWARDED_PROTO", "https"),
        )
        with self.assertRaises(ValueError):
            parse_header_pair("HTTP_X_FORWARDED_PROTO")
        with self.assertRaises(ValueError):
            parse_header_pair("a,b,c")

    def test_parse_ldap_options(self):
        import ldap

        self.assertEqual(
            parse_ldap_options("OPT_X_TLS_REQUIRE_CERT=OPT_X_TLS_NEVER"),
            {ldap.OPT_X_TLS_REQUIRE_CERT: ldap.OPT_X_TLS_NEVER},
        )
        self.assertEqual(parse_ldap_options("OPT_NETWORK_TIMEOUT=30"), {ldap.OPT_NETWORK_TIMEOUT: 30})
        with self.assertRaises(ValueError):
            parse_ldap_options("NOT_AN_OPTION=1")
        with self.assertRaises(ValueError):
            parse_ldap_options("OPT_X_TLS_REQUIRE_CERT=NOT_A_VALUE")

    def test_make_ldap_group_type(self):
        from django_auth_ldap.config import NestedActiveDirectoryGroupType

        self.assertIsInstance(make_ldap_group_type("NestedActiveDirectoryGroupType"), NestedActiveDirectoryGroupType)
        with self.assertRaises(ValueError):
            make_ldap_group_type("NotAGroupType")
    
    def test_make_ldap_group_type_with_args(self):
        from django_auth_ldap.config import MemberDNGroupType

        self.assertIsInstance(make_ldap_group_type("MemberDNGroupType", "member_attr_arg", "name_attr_arg"), MemberDNGroupType)
        with self.assertRaises(RuntimeError):
            make_ldap_group_type("MemberDNGroupType") # fails because of missing argument (member_attr)
    
    def test_make_ldap_search(self):
        import ldap
        from django_auth_ldap.config import LDAPSearch

        # Test all scopes as both uppercase and lowercase
        for scope in ["subtree", "onelevel", "base"]:
            for upper in [True, False]:
                with self.subTest(scope=scope, upper=upper):
                    if upper:
                        scope_to_use = scope.upper()
                    else:
                        scope_to_use = scope
                    search = make_ldap_search("OU=filegroups,DC=example,DC=com", scope=scope_to_use, filterstr="(objectClass=group)")
                    self.assertIsInstance(search, LDAPSearch)
                    self.assertEqual(search.base_dn, "OU=filegroups,DC=example,DC=com")
                    if scope_to_use.upper() == "SUBTREE":
                        self.assertEqual(search.scope, ldap.SCOPE_SUBTREE)
                    elif scope_to_use.upper() == "ONELEVEL":
                        self.assertEqual(search.scope, ldap.SCOPE_ONELEVEL)
                    elif scope_to_use.upper() == "BASE":
                        self.assertEqual(search.scope, ldap.SCOPE_BASE)
                    self.assertEqual(search.filterstr, "(objectClass=group)")
        
        with self.assertRaises(ValueError):
            make_ldap_search("DC=com", scope="EVERYTHING")
    
  


class SettingsEnvOverridesTests(SimpleTestCase):
    def test_group_settings_env_override(self):
        with reload_settings({"MREG_SUPERUSER_GROUP": "my-superusers"}) as reloaded:
            self.assertEqual(reloaded.SUPERUSER_GROUP, "my-superusers")
            self.assertEqual(reloaded.ADMINUSER_GROUP, "default-admin-group")

    def test_group_settings_have_defaults(self):
        with reload_settings() as reloaded:
            self.assertEqual(reloaded.SUPERUSER_GROUP, "default-super-group")
            self.assertEqual(reloaded.DNS_UNDERSCORE_GROUP, "default-dns-underscore-group")

    def test_secret_key_env_override(self):
        with reload_settings({"MREG_SECRET_KEY": "test-key"}) as reloaded:
            self.assertEqual(reloaded.SECRET_KEY, "test-key")

    def test_allowed_hosts_env_override(self):
        with reload_settings({"MREG_ALLOWED_HOSTS": "mreg.example.org, .example.com"}) as reloaded:
            self.assertEqual(reloaded.ALLOWED_HOSTS, ["mreg.example.org", ".example.com"])

    def test_secure_proxy_ssl_header_set(self):
        env = {"MREG_SECURE_PROXY_SSL_HEADER": "HTTP_X_FORWARDED_PROTO,https"}
        with reload_settings(env, drop=("SECURE_PROXY_SSL_HEADER",)) as reloaded:
            self.assertEqual(reloaded.SECURE_PROXY_SSL_HEADER, ("HTTP_X_FORWARDED_PROTO", "https"))

    def test_secure_proxy_ssl_header_unset(self):
        with reload_settings(drop=("SECURE_PROXY_SSL_HEADER",)) as reloaded:
            self.assertFalse(hasattr(reloaded, "SECURE_PROXY_SSL_HEADER"))

    def test_txt_auto_records_env_override(self):
        with reload_settings({"MREG_TXT_AUTO_RECORDS": "uio.no=v=spf1 -all"}) as reloaded:
            self.assertEqual(reloaded.TXT_AUTO_RECORDS, {"uio.no": ("v=spf1 -all",)})

    def test_txt_auto_records_default_example_org_when_unset(self):
        with reload_settings() as reloaded:
            self.assertEqual(reloaded.TXT_AUTO_RECORDS, {"example.org": ("v=spf1 -all",)})
    
    def test_txt_auto_records_opt_out_when_empty(self):
        with reload_settings({"MREG_TXT_AUTO_RECORDS": ""}) as reloaded:
            self.assertEqual(reloaded.TXT_AUTO_RECORDS, {})

    def test_mq_disabled_without_host(self):
        with reload_settings(drop=("MQ_CONFIG",)) as reloaded:
            self.assertFalse(hasattr(reloaded, "MQ_CONFIG"))

    def test_mq_enabled_when_required_variables_set(self):
        env = {
            "MREG_MQ_HOST": "mq.example.org",
            "MREG_MQ_EXCHANGE": "mreg",
            "MREG_MQ_USERNAME": "mquser",
            "MREG_MQ_PASSWORD": "mqpass",
            "MREG_MQ_SSL": "true",
            "MREG_MQ_VIRTUAL_HOST": "/vhost",
            "MREG_MQ_DECLARE": "true",
        }
        with reload_settings(env, drop=("MQ_CONFIG",)) as reloaded:
            self.assertEqual(
                reloaded.MQ_CONFIG,
                {
                    "host": "mq.example.org",
                    "ssl": True,
                    "virtual_host": "/vhost",
                    "exchange": "mreg",
                    "declare": True,
                    "username": "mquser",
                    "password": "mqpass",
                },
            )

    def test_mq_partial_config_exits(self):
        with self.assertRaises(SystemExit):
            with reload_settings({"MREG_MQ_HOST": "mq.example.org"}, drop=("MQ_CONFIG",)):
                pass  # pragma: no cover

    def test_ldap_advanced_settings(self):
        import ldap
        from django_auth_ldap.config import NestedActiveDirectoryGroupType

        env = {
            "MREG_AUTH_LDAP_MIRROR_GROUPS": "superusers,admins",
            "MREG_AUTH_LDAP_GLOBAL_OPTIONS": "OPT_X_TLS_REQUIRE_CERT=OPT_X_TLS_NEVER",
            "MREG_AUTH_LDAP_GROUP_TYPE": "NestedActiveDirectoryGroupType",
            "MREG_AUTH_LDAP_GROUP_SEARCH_BASE_DN": "OU=filegroups,DC=example,DC=com",
            "MREG_AUTH_LDAP_USER_ATTR_MAP": "first_name=givenName",
        }
        drop = (
            "AUTH_LDAP_MIRROR_GROUPS",
            "AUTH_LDAP_GLOBAL_OPTIONS",
            "AUTH_LDAP_GROUP_TYPE",
            "AUTH_LDAP_GROUP_SEARCH",
        )
        with reload_settings(env, drop=drop) as reloaded:
            self.assertEqual(reloaded.AUTH_LDAP_MIRROR_GROUPS, ["superusers", "admins"])
            self.assertEqual(
                reloaded.AUTH_LDAP_GLOBAL_OPTIONS,
                {ldap.OPT_X_TLS_REQUIRE_CERT: ldap.OPT_X_TLS_NEVER},
            )
            self.assertIsInstance(reloaded.AUTH_LDAP_GROUP_TYPE, NestedActiveDirectoryGroupType)
            self.assertEqual(reloaded.AUTH_LDAP_GROUP_SEARCH.base_dn, "OU=filegroups,DC=example,DC=com")
            self.assertEqual(reloaded.AUTH_LDAP_GROUP_SEARCH.scope, ldap.SCOPE_SUBTREE)
            self.assertEqual(reloaded.AUTH_LDAP_GROUP_SEARCH.filterstr, "(objectClass=group)")
            self.assertEqual(reloaded.AUTH_LDAP_USER_ATTR_MAP, {"first_name": "givenName"})

    def test_ldap_group_with_args(self):
        from django_auth_ldap.config import MemberDNGroupType

        env = {
            "MREG_AUTH_LDAP_GROUP_TYPE": "MemberDNGroupType",
            "MREG_AUTH_LDAP_GROUP_ARGS": "member_attr_arg,name_attr_arg",
        }
        # Can instantiate the group type with the provided arguments
        with reload_settings(env, drop=("AUTH_LDAP_GROUP_TYPE", "AUTH_LDAP_GROUP_ARGS")) as reloaded:
            self.assertIsInstance(reloaded.AUTH_LDAP_GROUP_TYPE, MemberDNGroupType)

    def test_ldap_group_without_args(self):
        from django_auth_ldap.config import NestedActiveDirectoryGroupType

        env = {
            "MREG_AUTH_LDAP_GROUP_TYPE": "NestedActiveDirectoryGroupType",
            "MREG_AUTH_LDAP_GROUP_ARGS": "",
        }
        # Can instantiate the group type with the provided arguments
        with reload_settings(env, drop=("AUTH_LDAP_GROUP_TYPE", "AUTH_LDAP_GROUP_ARGS")) as reloaded:
            self.assertIsInstance(reloaded.AUTH_LDAP_GROUP_TYPE, NestedActiveDirectoryGroupType)


    def test_ldap_mirror_groups_unset_not_defined(self):
        with reload_settings(drop=("AUTH_LDAP_MIRROR_GROUPS",)) as reloaded:
            self.assertFalse(hasattr(reloaded, "AUTH_LDAP_MIRROR_GROUPS"))

    def test_sentry_initialized_when_dsn_set(self):
        from sentry_sdk.integrations.django import DjangoIntegration

        dsn = "https://example@sentry.example.org/1"
        with patch("sentry_sdk.init") as mock_init:
            with reload_settings({"MREG_SENTRY_DSN": dsn}) as reloaded:
                self.assertEqual(reloaded.MREG_SENTRY_DSN, dsn)
        mock_init.assert_called_once()
        _, kwargs = mock_init.call_args
        self.assertEqual(kwargs["dsn"], dsn)
        self.assertTrue(any(isinstance(i, DjangoIntegration) for i in kwargs["integrations"]))

    def test_sentry_disabled_by_default(self):
        with reload_settings() as reloaded:
            self.assertEqual(reloaded.MREG_SENTRY_DSN, "")

    def test_protected_attrs_env_override_none(self):
        env_backup = dict(os.environ)
        try:
            os.environ["MREG_NO_PROTECTED_POLICY_ATTRIBUTES"] = "true"
            os.environ["MREG_PROTECTED_POLICY_ATTRIBUTES"] = "foo=bar"
            reloaded = importlib.reload(app_settings)
            self.assertEqual(reloaded.MREG_PROTECTED_POLICY_ATTRIBUTES, [])
        finally:
            os.environ.clear()
            os.environ.update(env_backup)
            importlib.reload(app_settings)

    def test_protected_attrs_env_override_parse(self):
        env_backup = dict(os.environ)
        try:
            os.environ["MREG_NO_PROTECTED_POLICY_ATTRIBUTES"] = "false"
            os.environ["MREG_PROTECTED_POLICY_ATTRIBUTES"] = "alpha=Alpha"
            reloaded = importlib.reload(app_settings)
            self.assertEqual(
                reloaded.MREG_PROTECTED_POLICY_ATTRIBUTES,
                [{"name": "alpha", "description": "Alpha"}],
            )
        finally:
            os.environ.clear()
            os.environ.update(env_backup)
            importlib.reload(app_settings)

    def test_profiling_enabled_configures_silk(self):
        env_backup = dict(os.environ)
        original_installed_apps = list(app_settings.INSTALLED_APPS)
        original_middleware = list(app_settings.MIDDLEWARE)
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                os.environ["MREG_PROFILING_ENABLED"] = "true"
                os.environ["MREG_SILKY_PYTHON_PROFILER_RESULT_PATH"] = tmpdir

                with patch.dict(sys.modules, {"silk": ModuleType("silk")}):
                    reloaded = importlib.reload(app_settings)

                    self.assertIn("silk", reloaded.INSTALLED_APPS)
                    self.assertEqual(reloaded.MIDDLEWARE[0], "silk.middleware.SilkyMiddleware")
                    self.assertTrue(reloaded.SILKY_DYNAMIC_PROFILING)
        finally:
            os.environ.clear()
            os.environ.update(env_backup)
            app_settings.INSTALLED_APPS = original_installed_apps
            app_settings.MIDDLEWARE = original_middleware
            importlib.reload(app_settings)

    def test_profiling_enabled_requires_silk(self):
        env_backup = dict(os.environ)
        try:
            os.environ["MREG_PROFILING_ENABLED"] = "true"
            with patch.dict(sys.modules, {"silk": None}):
                with self.assertRaises(SystemExit):
                    importlib.reload(app_settings)
        finally:
            os.environ.clear()
            os.environ.update(env_backup)
            importlib.reload(app_settings)

    def test_profiling_creates_missing_result_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result_path = os.path.join(tmpdir, "profiles")
            try:
                with patch.dict(
                    os.environ,
                    {
                        "MREG_PROFILING_ENABLED": "true",
                        "MREG_SILKY_PYTHON_PROFILER_RESULT_PATH": result_path,
                    },
                ):
                    with patch.dict(sys.modules, {"silk": ModuleType("silk")}):
                        importlib.reload(app_settings)

                self.assertTrue(os.path.isdir(result_path))
            finally:
                importlib.reload(app_settings)

    def test_profiling_exits_when_result_directory_cannot_be_created(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result_path = os.path.join(tmpdir, "profiles")
            try:
                with patch.dict(
                    os.environ,
                    {
                        "MREG_PROFILING_ENABLED": "true",
                        "MREG_SILKY_PYTHON_PROFILER_RESULT_PATH": result_path,
                    },
                ):
                    with patch.dict(sys.modules, {"silk": ModuleType("silk")}):
                        with patch.object(app_settings.Path, "mkdir", side_effect=OSError("denied")):
                            with self.assertRaises(SystemExit):
                                importlib.reload(app_settings)
            finally:
                importlib.reload(app_settings)

    def test_profiling_exits_when_result_path_is_file(self):
        with tempfile.NamedTemporaryFile() as result_file:
            try:
                with patch.dict(
                    os.environ,
                    {
                        "MREG_PROFILING_ENABLED": "true",
                        "MREG_SILKY_PYTHON_PROFILER_RESULT_PATH": result_file.name,
                    },
                ):
                    with patch.dict(sys.modules, {"silk": ModuleType("silk")}):
                        with self.assertRaises(SystemExit):
                            importlib.reload(app_settings)
            finally:
                importlib.reload(app_settings)
