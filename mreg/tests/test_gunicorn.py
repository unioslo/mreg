import runpy

from django.test import SimpleTestCase, override_settings
from unittest_parametrize import ParametrizedTestCase, param, parametrize


class GunicornSnapshotTimeoutTests(ParametrizedTestCase, SimpleTestCase):
    @parametrize("duration", [param(900, id="default"), param(1800, id="custom")])
    def test_worker_timeouts_allow_the_effective_snapshot_budget(self, duration):
        with override_settings(MREG_SNAPSHOT_MAX_DURATION_SECONDS=duration):
            config = runpy.run_module("mregsite.gunicorn")
        self.assertGreaterEqual(config["timeout"], duration + 60)
        self.assertGreaterEqual(config["graceful_timeout"], duration + 60)
