from unittest.mock import patch
from mregsite import settings

from django.test import TestCase


class SettingsTestCase(TestCase):
    """This class defines the test suite for settings.py."""

    def test_get_pool_settings_enabled(self):
        with patch.object(settings, "MREG_DB_POOL_ENABLED", True):
            result = settings.get_pool_settings()
        assert isinstance(result, dict)
        assert "max_size" in result


    def test_get_pool_settings_disabled(self):
        with patch.object(settings, "MREG_DB_POOL_ENABLED", False):
            result = settings.get_pool_settings()
        assert result is False
