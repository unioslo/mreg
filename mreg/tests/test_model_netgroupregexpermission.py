from django.core.exceptions import ValidationError
from django.test import TestCase

from mreg.models import NetGroupRegexPermission, Network

from .base import clean_and_save


class NetGroupRegexPermissionTestCase(TestCase):
    def create_sample_permission(self):
        perm = NetGroupRegexPermission(
            group="testgroup", range="10.0.0.0/25", regex=r".*\.example\.org$"
        )
        clean_and_save(perm)
        return perm

    def test_model_create(self):
        old_count = NetGroupRegexPermission.objects.count()
        perm = self.create_sample_permission()
        self.assertGreater(NetGroupRegexPermission.objects.count(), old_count)
        str(perm)

    def test_model_find_perm(self):
        perm = self.create_sample_permission()
        find_perm = NetGroupRegexPermission.find_perm
        qs = find_perm(
            (
                "randomgroup",
                "testgroup",
            ),
            "www.example.org",
            "10.0.0.1",
        )
        self.assertEqual(qs.first(), perm)
        qs = find_perm(
            "testgroup",
            "www.example.org",
            (
                "2.2.2.2",
                "10.0.0.1",
            ),
        )
        self.assertEqual(qs.first(), perm)

    def test_model_invalid_find_perm(self):
        def _assert(groups, hostname, ips):
            with self.assertRaises(ValueError):
                find_perm(groups, hostname, ips)

        find_perm = NetGroupRegexPermission.find_perm
        # hostname is not a string
        _assert("testgroup", ("www.example.org",), "10.0.0.1")
        # group is not string/tuple/list
        _assert({"name": "testgroup"}, "www.example.org", "10.0.0.1")
        _assert("testgroup", "www.example.org", None)

    def test_model_reject_invalid(self):
        # Reject invalid range. Hostbit set.
        perm = NetGroupRegexPermission(
            group="testgroup", range="10.0.0.1/25", regex=r".*\.example\.org$"
        )
        with self.assertRaises(ValidationError) as cm:
            clean_and_save(perm)
        self.assertEqual(
            str(cm.exception), "{'range': ['10.0.0.1/25 has host bits set']}"
        )
        # Reject invalid regex.
        perm = NetGroupRegexPermission(
            group="testgroup", range="10.0.0.0/25", regex=r".*\.ex(ample\.org$"
        )
        with self.assertRaises(ValidationError) as cm:
            clean_and_save(perm)
        self.assertEqual(
            str(cm.exception),
            "{'regex': ['missing ), unterminated subpattern at position 6']}",
        )

    def test_model_clean_permissions(self):
        # Make sure that permissions are removed if a Network with equal
        # or larger network is removed. Removed by code in signals.py.
        self.network_v4 = Network(network="10.0.0.0/24")
        self.network_v6 = Network(network="2001:db8::/64")
        clean_and_save(self.network_v4)
        clean_and_save(self.network_v6)
        v4perm = NetGroupRegexPermission(
            group="testgroup", range="10.0.0.0/25", regex=r".*\.example\.org$"
        )
        clean_and_save(v4perm)
        v6perm = NetGroupRegexPermission(
            group="testgroup", range=self.network_v6.network, regex=r".*\.example\.org$"
        )
        clean_and_save(v6perm)
        self.assertEqual(NetGroupRegexPermission.objects.count(), 2)
        self.network_v4.delete()
        self.assertEqual(NetGroupRegexPermission.objects.count(), 1)
        self.assertEqual(NetGroupRegexPermission.objects.first(), v6perm)
        self.network_v6.delete()
        self.assertEqual(NetGroupRegexPermission.objects.count(), 0)
