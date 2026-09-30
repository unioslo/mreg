import importlib
import sys
import types
from unittest.mock import patch

from django.test import TestCase
from django.test.utils import override_settings

import mregsite.urls


class UrlsTests(TestCase):
    def test_silk_urls_are_added_when_profiling_is_enabled(self):
        silk_urls = types.ModuleType("silk.urls")
        silk_urls.app_name = "silk"
        silk_urls.urlpatterns = []

        with override_settings(MREG_PROFILING_ENABLED=True), patch.dict(sys.modules, {"silk.urls": silk_urls}):
            reloaded = importlib.reload(mregsite.urls)
            self.assertTrue(any(pattern.pattern._route == "silk/" for pattern in reloaded.urlpatterns))

        importlib.reload(mregsite.urls)
