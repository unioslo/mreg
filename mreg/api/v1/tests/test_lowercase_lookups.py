"""Regression tests for API lookups that bypassed manager normalization."""

from urllib.parse import urlencode

from django.contrib.auth.models import Group

from hostpolicy.models import HostPolicyAtom, HostPolicyRole
from mreg.models.host import Host, HostGroup

from .tests import MregAPITestCase


class LowerCaseAPILookupTests(MregAPITestCase):
    def setUp(self):
        super().setUp()
        self.atom = HostPolicyAtom.objects.create(name="alpha")
        self.role = HostPolicyRole.objects.create(name="role")
        self.role.atoms.add(self.atom)
        self.host = Host.objects.create(name="host.example.org")
        self.role.hosts.add(self.host)
        self.group = HostGroup.objects.create(name="hostgroup")
        self.group.hosts.add(self.host)

    def test_uppercase_m2m_parent_and_member(self):
        paths = [
            "/hostpolicy/roles/ROLE/atoms/ALPHA",
            "/hostpolicy/roles/ROLE/hosts/HOST.EXAMPLE.ORG",
            "/hostgroups/HOSTGROUP/hosts/HOST.EXAMPLE.ORG",
        ]
        for path in paths:
            with self.subTest(path=path):
                self.assert_get(path)
                self.assert_delete(path)
        self.assertFalse(self.role.atoms.exists())
        self.assertFalse(self.role.hosts.exists())
        self.assertFalse(self.group.hosts.exists())
        self.atom.refresh_from_db()
        self.host.refresh_from_db()

    def test_uppercase_nested_hostgroup(self):
        child = HostGroup.objects.create(name="child")
        self.group.groups.add(child)
        self.assert_get("/hostgroups/HOSTGROUP/groups/CHILD")
        self.assert_delete("/hostgroups/HOSTGROUP/groups/CHILD")
        self.assertFalse(self.group.groups.exists())
        child.refresh_from_db()

    def test_uppercase_member_addition(self):
        self.group.hosts.remove(self.host)
        self.assert_post("/hostgroups/HOSTGROUP/hosts/", {"name": "HOST.EXAMPLE.ORG"})
        self.assertEqual(self.group.hosts.get(), self.host)

    def test_owner_names_retain_case_sensitivity(self):
        owner = Group.objects.create(name="MixedCaseOwner")
        self.group.owners.add(owner)
        self.assert_get("/hostgroups/HOSTGROUP/owners/MixedCaseOwner")
        self.assert_get_and_404("/hostgroups/HOSTGROUP/owners/mixedcaseowner")
        self.assert_delete_and_404("/hostgroups/HOSTGROUP/owners/mixedcaseowner")
        self.assertTrue(self.group.owners.filter(pk=owner.pk).exists())

    def test_regex_filter_preserves_uppercase_escapes(self):
        HostPolicyAtom.objects.create(name="123")
        query = urlencode({"name__regex": r"^\D+$"})
        response = self.assert_get(f"/hostpolicy/atoms/?{query}")
        self.assertEqual([item["name"] for item in response.json()["results"]], ["alpha"])

    def test_filter_by_related_name(self):
        query = urlencode({"atoms__name__exact": "ALPHA"})
        response = self.assert_get(f"/hostpolicy/roles/?{query}")
        self.assertEqual([item["name"] for item in response.json()["results"]], ["role"])
