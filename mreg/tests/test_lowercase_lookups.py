"""Exercise field lookups through the ORM, including ordinary querysets."""

from ipaddress import ip_network

from django.contrib.auth.models import Group
from django.db import models
from django.db.models import F, Q, Subquery, Value
from django.db.models.functions import Upper
from django.shortcuts import get_object_or_404
from django.test import TestCase

from hostpolicy.models import HostPolicyAtom, HostPolicyRole
from mreg.models.host import Host, HostGroup
from mreg.models.zone import ReverseZone


class LowerCaseLookupTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.atom = HostPolicyAtom.objects.create(name="alpha", description="MixedCase")
        cls.other_atom = HostPolicyAtom.objects.create(name="123", description="123")
        cls.role = HostPolicyRole.objects.create(name="role")
        cls.role.atoms.add(cls.atom)
        cls.host = Host.objects.create(name="host.example.org")
        cls.hostgroup = HostGroup.objects.create(name="hostgroup")
        cls.hostgroup.hosts.add(cls.host)
        cls.owner = Group.objects.create(name="MixedCaseOwner")
        cls.hostgroup.owners.add(cls.owner)

    def atoms(self):
        # An ordinary queryset proves normalization does not depend on a manager.
        return models.QuerySet(model=HostPolicyAtom)

    def test_direct_chained_and_shortcut_lookups(self):
        querysets = [
            HostPolicyAtom.objects,
            HostPolicyAtom.objects.all().order_by("name"),
            self.atoms().filter(description="MixedCase"),
            HostPolicyAtom._base_manager,
        ]
        for queryset in querysets:
            with self.subTest(queryset=type(queryset).__name__):
                self.assertEqual(queryset.get(name="ALPHA"), self.atom)
                self.assertEqual(queryset.get(name__exact="ALPHA"), self.atom)
        self.assertEqual(get_object_or_404(HostPolicyAtom, name="ALPHA"), self.atom)
        self.assertEqual(get_object_or_404(self.atoms(), name="ALPHA"), self.atom)

    def test_nested_q_objects_and_exclusion(self):
        predicate = Q(name="ALPHA") & (Q(description="MixedCase") | Q(name="MISSING"))
        self.assertEqual(self.atoms().get(predicate), self.atom)
        self.assertQuerySetEqual(self.atoms().filter(~predicate), [self.other_atom])
        self.assertQuerySetEqual(self.atoms().exclude(name="ALPHA"), [self.other_atom])
        # Building a lookup must not mutate a reusable Q object.
        self.assertEqual(predicate.children[0], ("name", "ALPHA"))

    def test_collections_and_generators(self):
        names = ["ALPHA", "MISSING"]
        for values in [names, tuple(names), iter(names)]:
            with self.subTest(values=type(values).__name__):
                self.assertQuerySetEqual(self.atoms().filter(name__in=values), [self.atom])
        self.assertEqual(names, ["ALPHA", "MISSING"])
        self.assertQuerySetEqual(self.atoms().filter(name__in=[]), [])
        self.assertQuerySetEqual(self.atoms().filter(name__in=[None, "ALPHA"]), [self.atom])
        self.assertQuerySetEqual(self.atoms().filter(name__range=("A", "AZ")), [self.atom])

    def test_literal_operators(self):
        for lookup, value in [
            ("gt", "ALPG"), ("gte", "ALPHA"),
            ("lt", "ALPI"), ("lte", "ALPHA"),
            ("contains", "LPH"), ("startswith", "AL"), ("endswith", "HA"),
            ("iexact", "ALPHA"), ("icontains", "LPH"),
            ("istartswith", "AL"), ("iendswith", "HA"),
        ]:
            with self.subTest(lookup=lookup):
                queryset = self.atoms().exclude(pk=self.other_atom.pk)
                self.assertQuerySetEqual(queryset.filter(**{f"name__{lookup}": value}), [self.atom])

    def test_literal_sql_wildcards_remain_escaped(self):
        atom = HostPolicyAtom.objects.create(name="a%b_c")
        HostPolicyAtom.objects.create(name="axbxc")
        self.assertQuerySetEqual(self.atoms().filter(name__contains="A%B_"), [atom])

    def test_related_manager_and_forward_reverse_joins(self):
        self.assertEqual(self.role.atoms.all().get(name="ALPHA"), self.atom)
        self.assertEqual(HostPolicyRole.objects.get(atoms__name="ALPHA"), self.role)
        self.assertEqual(self.atoms().get(roles__name="ROLE"), self.atom)
        self.assertEqual(HostGroup.objects.get(hosts__name="HOST.EXAMPLE.ORG"), self.hostgroup)
        self.assertEqual(self.hostgroup.hosts.all().get(name="HOST.EXAMPLE.ORG"), self.host)

    def test_prefetched_related_manager(self):
        role = HostPolicyRole.objects.prefetch_related("atoms").get(pk=self.role.pk)
        self.assertEqual(role.atoms.all().get(name="ALPHA"), self.atom)

    def test_regex_patterns_are_preserved(self):
        for lookup in ["regex", "iregex"]:
            for pattern, expected in [
                (r"^\D+$", [self.atom]),
                (r"^\S+$", [self.other_atom, self.atom]),
                (r"^\W+$", []),
            ]:
                for queryset in [HostPolicyAtom.objects, self.atoms()]:
                    with self.subTest(lookup=lookup, pattern=pattern, queryset=type(queryset).__name__):
                        self.assertQuerySetEqual(
                            queryset.filter(**{f"name__{lookup}": pattern}).order_by("name"), expected,
                        )
        self.assertQuerySetEqual(self.atoms().filter(name__regex="^[A-Z]+$"), [])
        self.assertQuerySetEqual(self.atoms().filter(name__iregex="^[A-Z]+$"), [self.atom])

    def test_plain_fields_and_owner_names_keep_case_sensitivity(self):
        self.assertFalse(self.atoms().filter(description="mixedcase").exists())
        self.assertEqual(Group.objects.get(name="MixedCaseOwner"), self.owner)
        self.assertFalse(Group.objects.filter(name="mixedcaseowner").exists())
        self.assertFalse(HostGroup.objects.filter(owners__name="mixedcaseowner").exists())
        self.assertEqual(self.hostgroup.owners.get(name="MixedCaseOwner"), self.owner)

    def test_null_lookup(self):
        self.assertFalse(self.atoms().filter(name=None).exists())
        self.assertEqual(self.atoms().filter(name__isnull=False).count(), 2)

    def test_expressions_are_not_normalized(self):
        self.assertFalse(self.atoms().filter(name=Value("ALPHA")).exists())
        self.assertEqual(self.atoms().get(name__iexact=Value("ALPHA")), self.atom)
        self.assertEqual(self.atoms().get(name=F("description")), self.other_atom)
        self.assertFalse(self.atoms().filter(name__contains=Value("LPH")).exists())

    def test_mixed_expression_and_literal_collections(self):
        values = ["ALPHA", Value("123")]
        self.assertQuerySetEqual(self.atoms().filter(name__in=values).order_by("name"), [self.other_atom, self.atom])
        self.assertEqual(values[0], "ALPHA")
        self.assertFalse(self.atoms().filter(name__in=[Value("ALPHA")]).exists())
        self.assertQuerySetEqual(self.atoms().filter(name__range=["A", Value("az")]), [self.atom])

    def test_subqueries_are_not_normalized(self):
        values = self.atoms().filter(pk=self.atom.pk).annotate(upper_name=Upper("name")).values("upper_name")
        self.assertFalse(self.atoms().filter(name__in=values).exists())
        self.assertFalse(self.atoms().filter(name=Subquery(values[:1])).exists())
        values = self.atoms().filter(pk=self.atom.pk).values("name")
        self.assertEqual(self.atoms().get(name__in=values), self.atom)

    def test_transforms_are_not_normalized(self):
        # Upper inherits the source field as its output_field, so it also sees
        # that field's registered lookups. Its uppercase output must be preserved.
        queryset = self.atoms().annotate(upper_name=Upper("name"))
        self.assertEqual(queryset.get(upper_name="ALPHA"), self.atom)
        self.assertFalse(queryset.filter(upper_name="alpha").exists())
        self.assertEqual(queryset.get(upper_name__in=["ALPHA"]), self.atom)

    def test_exact_lookup_leaves_column_unwrapped(self):
        sql, params = self.atoms().filter(name="ALPHA").query.sql_with_params()
        self.assertEqual(params, ("alpha",))
        self.assertNotIn("LOWER(", sql.upper())
        self.assertNotIn("UPPER(", sql.upper())

    def test_netmanager_composition(self):
        zone = ReverseZone.objects.create(
            name="2.0.192.in-addr.arpa", primary_ns="ns.example.org", email="hostmaster@example.org",
        )
        self.assertEqual(
            ReverseZone.objects.get(name="2.0.192.IN-ADDR.ARPA"), zone,
        )
        self.assertEqual(
            ReverseZone.objects.filter(network=ip_network("192.0.2.0/24")).get(name="2.0.192.IN-ADDR.ARPA"), zone,
        )

    def test_uppercase_storage_and_get_or_create(self):
        atom = HostPolicyAtom.objects.create(name="NEWATOM")
        atom.refresh_from_db()
        self.assertEqual(atom.name, "newatom")
        result, created = HostPolicyAtom.objects.get_or_create(name="NEWATOM")
        self.assertFalse(created)
        self.assertEqual(result, atom)
