import importlib
import os
from django.test import TestCase

import mregsite.settings as app_settings


class SettingsHelpersTests(TestCase):
    def test_envvar_bool_and_casting(self):
        os.environ["MREG_TEST_BOOL"] = "original"
        original = os.environ.get("MREG_TEST_BOOL")
        try:
            os.environ["MREG_TEST_BOOL"] = "true"
            self.assertTrue(app_settings.envvar("MREG_TEST_BOOL", False))

            os.environ["MREG_TEST_BOOL"] = "false"
            self.assertFalse(app_settings.envvar("MREG_TEST_BOOL", True))

            os.environ["MREG_TEST_BOOL"] = "maybe"
            self.assertTrue(app_settings.envvar("MREG_TEST_BOOL", True))
        finally:
            if original is None:
                os.environ.pop("MREG_TEST_BOOL", None) # pragma: no cover
            else:
                os.environ["MREG_TEST_BOOL"] = original

        os.environ["MREG_TEST_INT"] = "original"
        original_int = os.environ.get("MREG_TEST_INT")
        try:
            os.environ["MREG_TEST_INT"] = "not-an-int"
            self.assertEqual(app_settings.envvar("MREG_TEST_INT", 5), 5)
        finally:
            if original_int is None:
                os.environ.pop("MREG_TEST_INT", None) # pragma: no cover
            else:
                os.environ["MREG_TEST_INT"] = original_int

    def test_parse_protected_attrs(self):
        result = app_settings.parse_protected_attrs(" ,=ignored,foo=,bar=baz ")
        self.assertEqual(
            result,
            [
                {"name": "foo", "description": "Protected attribute foo."},
                {"name": "bar", "description": "baz"},
            ],
        )

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
