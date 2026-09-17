"""Tests for LowerCaseManager / LowerCaseQuerySet.

NOTE: Lots of AI slop comments in this module, but the tests themselves are pretty sound.

Two tiers of tests:

1. `LowerCaseManagerTestCase` — a throwaway test-only model, exercising the
   manager in isolation (including that plain CharFields are left untouched).
2. `LowerCaseManagerTestsMixin` — shared behavioural tests that any real model
   using the manager can opt into by subclassing `(mixin, TestCase)`, setting
   `model`, and implementing `make_instance`. `test_all_models_covered`
   guards that every model with the manager has such a subclass.
"""

from unittest import expectedFailure

from django.apps import apps
from django.db import connection, models
from django.db.models import Q, Value
from django.test import TestCase

from hostpolicy.models import HostPolicyAtom, HostPolicyRole
from mreg.fields import LowerCaseCharField
from mreg.managers import LowerCaseManager, _lowercase_field_names
from mreg.models.base import Label, NameServer
from mreg.models.host import Host, HostGroup
from mreg.models.network import Network
from mreg.models.network_policy import Community, NetworkPolicy, NetworkPolicyAttribute
from mreg.models.resource_records import Cname, Naptr
from mreg.models.zone import ForwardZone, ForwardZoneDelegation, ReverseZone


def models_with_lowercase_manager() -> list[type[models.Model]]:
    """All registered models that expose a LowerCaseManager and have a field to test."""
    result: list[type[models.Model]] = []
    for model in apps.get_models():
        if ".tests" in model.__module__:  # skip test-only models like LowerCaseModel
            continue
        if any(isinstance(m, LowerCaseManager) for m in model._meta.managers):
            if _lowercase_field_names(model):
                result.append(model)
    return result


class LowerCaseModel(models.Model):
    """Test-only model with one lowercased field and one plain field."""

    lower = LowerCaseCharField(max_length=100)
    plain = models.CharField(max_length=100)

    objects = LowerCaseManager()

    class Meta:
        app_label = "mreg"


class LowerCaseManagerTestCase(TestCase):
    """Test cases for LowerCaseManager using a test-only model."""
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(LowerCaseModel)

    @classmethod
    def tearDownClass(cls):
        with connection.schema_editor() as schema_editor:
            schema_editor.delete_model(LowerCaseModel)
        super().tearDownClass()

    def setUp(self):
        # LowerCaseCharField lowercases on save, so `lower` is stored as "abc".
        LowerCaseModel.objects.create(lower="abc", plain="ABC")

    def test_filter_lowercases_query_value(self):
        self.assertTrue(LowerCaseModel.objects.filter(lower="ABC").exists())

    def test_get_lowercases_query_value(self):
        self.assertEqual(LowerCaseModel.objects.get(lower="AbC").lower, "abc")

    def test_exclude_lowercases_query_value(self):
        self.assertFalse(LowerCaseModel.objects.exclude(lower="ABC").exists())

    def test_plain_field_not_lowercased(self):
        # Non-LowerCaseCharField values must be left untouched.
        self.assertTrue(LowerCaseModel.objects.filter(plain="ABC").exists())
        self.assertFalse(LowerCaseModel.objects.filter(plain="abc").exists())

    def test_lookup_suffix_still_lowercased(self):
        # field name is split on "__", so lower__contains still targets `lower`.
        self.assertTrue(LowerCaseModel.objects.filter(lower__contains="AB").exists())

    def test_chained_queryset_still_lowercases(self):
        # Lower-casing lives on the queryset, so a chained call also lowercases.
        self.assertTrue(LowerCaseModel.objects.all().filter(lower="ABC").exists())

    # --- Known gaps: the manager only lowercases plain str keyword values, so
    # these forms slip through. Tests assert the *desired* behaviour and are
    # marked expectedFailure; if the manager is fixed they turn into unexpected
    # successes (a failure), prompting removal of the decorator. See also
    # LowerCaseManagerRelatedLookupTestCase for the related-lookup gap.

    @expectedFailure
    def test_q_object_value_lowercased(self):
        # Q(...) is passed positionally, so it's never inspected.
        self.assertTrue(LowerCaseModel.objects.filter(Q(lower="ABC")).exists())

    @expectedFailure
    def test_in_lookup_values_lowercased(self):
        # List values aren't str, so their elements aren't lowercased.
        self.assertTrue(LowerCaseModel.objects.filter(lower__in=["ABC"]).exists())

    @expectedFailure
    def test_expression_value_lowercased(self):
        # Value(...) is an expression, not a str.
        self.assertTrue(LowerCaseModel.objects.filter(lower=Value("ABC")).exists())

    @expectedFailure
    def test_regex_metacharacters_not_mangled(self):
        # .lower() corrupts escaped metaclasses: \D (non-digit) -> \d (digit).
        # "abc" is all non-digits so \D should match; mangled to \d it misses.
        self.assertTrue(LowerCaseModel.objects.filter(lower__regex=r"\D").exists())

    @expectedFailure
    def test_iregex_metacharacters_not_mangled(self):
        # Same corruption on the case-insensitive variant.
        self.assertTrue(LowerCaseModel.objects.filter(lower__iregex=r"\D").exists())


class LowerCaseManagerTestsMixin:
    """Mixin that enables shared tests for any model using LowerCaseManager.

    Ideally this would have been an ABC instead of a mixin, but I'm not sure
    if Django supports creating a `TestCase` class that is also an ABC.
    """

    model: type[models.Model] = models.Model  # override in subclass

    def make_instance(self, **overrides: object) -> models.Model:
        """Create and return a saved, valid instance of `self.model`.

        Lowercased fields must be given values containing letters so the
        manager's lowercasing is observable. Each subclass knows its own
        required fields, FKs and unique constraints.
        """
        raise NotImplementedError

    @property
    def lower_field(self) -> str:
        """First LowerCaseCharField on the model — the field we query against."""
        return sorted(_lowercase_field_names(self.model))[0]

    def _stored_value(self, obj: models.Model) -> str:
        value = getattr(obj, self.lower_field)
        assert value and value != value.upper(), (
            f"{self.model.__name__}.{self.lower_field} test value must contain "
            "letters so lowercasing is observable"
        )
        return value

    def test_filter_lowercases_query_value(self):
        obj = self.make_instance()
        value = self._stored_value(obj)
        qs = self.model.objects.filter(**{self.lower_field: value.upper()})
        self.assertIn(obj, qs)

    def test_get_lowercases_query_value(self):
        obj = self.make_instance()
        value = self._stored_value(obj)
        found = self.model.objects.get(**{self.lower_field: value.upper()})
        self.assertEqual(found.pk, obj.pk)

    def test_exclude_lowercases_query_value(self):
        obj = self.make_instance()
        value = self._stored_value(obj)
        qs = self.model.objects.exclude(**{self.lower_field: value.upper()})
        self.assertNotIn(obj, qs)

    def test_lookup_suffix_still_lowercased(self):
        obj = self.make_instance()
        value = self._stored_value(obj)
        qs = self.model.objects.filter(**{f"{self.lower_field}__contains": value.upper()})
        self.assertIn(obj, qs)


class HostGroupLowerCaseTests(LowerCaseManagerTestsMixin, TestCase):
    model = HostGroup

    def make_instance(self, **overrides):
        return HostGroup.objects.create(**{"name": "lowered", **overrides})


class HostLowerCaseTests(LowerCaseManagerTestsMixin, TestCase):
    model = Host

    def make_instance(self, **overrides):
        return Host.objects.create(**{"name": "lowered.example.org", **overrides})


class NameServerLowerCaseTests(LowerCaseManagerTestsMixin, TestCase):
    model = NameServer

    def make_instance(self, **overrides):
        return NameServer.objects.create(**{"name": "ns.example.org", **overrides})


class LabelLowerCaseTests(LowerCaseManagerTestsMixin, TestCase):
    model = Label

    def make_instance(self, **overrides):
        return Label.objects.create(**{"name": "lowered", "description": "d", **overrides})


class NetworkPolicyLowerCaseTests(LowerCaseManagerTestsMixin, TestCase):
    model = NetworkPolicy

    def make_instance(self, **overrides):
        return NetworkPolicy.objects.create(**{"name": "lowered", **overrides})


class NetworkPolicyAttributeLowerCaseTests(LowerCaseManagerTestsMixin, TestCase):
    model = NetworkPolicyAttribute

    def make_instance(self, **overrides):
        return NetworkPolicyAttribute.objects.create(**{"name": "lowered", **overrides})


class CommunityLowerCaseTests(LowerCaseManagerTestsMixin, TestCase):
    model = Community

    def make_instance(self, **overrides):
        network = Network.objects.create(network="10.0.0.0/24")
        return Community.objects.create(**{"name": "lowered", "network": network, **overrides})


class CnameLowerCaseTests(LowerCaseManagerTestsMixin, TestCase):
    model = Cname

    def make_instance(self, **overrides):
        host = Host.objects.create(name="host.example.org")
        return Cname.objects.create(**{"host": host, "name": "lowered.example.org", **overrides})


class NaptrLowerCaseTests(LowerCaseManagerTestsMixin, TestCase):
    model = Naptr  # lower_field is "replacement" (first alphabetically)

    def make_instance(self, **overrides):
        host = Host.objects.create(name="host.example.org")
        defaults = {
            "host": host,
            "preference": 1,
            "order": 1,
            "flag": "a",
            "service": "service",
            "regex": "^naptrregex",
            "replacement": "lowered",
        }
        return Naptr.objects.create(**{**defaults, **overrides})


class ForwardZoneLowerCaseTests(LowerCaseManagerTestsMixin, TestCase):
    model = ForwardZone

    def make_instance(self, **overrides):
        defaults = {
            "name": "lowered.org",
            "primary_ns": "ns.example.org",
            "email": "hostmaster@example.org",
        }
        return ForwardZone.objects.create(**{**defaults, **overrides})


class ReverseZoneLowerCaseTests(LowerCaseManagerTestsMixin, TestCase):
    model = ReverseZone

    def make_instance(self, **overrides):
        defaults = {
            "name": "0.10.in-addr.arpa",
            "primary_ns": "ns.example.org",
            "email": "hostmaster@example.org",
        }
        return ReverseZone.objects.create(**{**defaults, **overrides})


class ForwardZoneDelegationLowerCaseTests(LowerCaseManagerTestsMixin, TestCase):
    model = ForwardZoneDelegation

    def make_instance(self, **overrides):
        zone = ForwardZone.objects.create(
            name="example.org", primary_ns="ns.example.org", email="hostmaster@example.org"
        )
        return ForwardZoneDelegation.objects.create(
            **{"zone": zone, "name": "sub.example.org", **overrides}
        )


class HostPolicyAtomLowerCaseTests(LowerCaseManagerTestsMixin, TestCase):
    model = HostPolicyAtom

    def make_instance(self, **overrides):
        return HostPolicyAtom.objects.create(**{"name": "lowered", "description": "d", **overrides})


class HostPolicyRoleLowerCaseTests(LowerCaseManagerTestsMixin, TestCase):
    model = HostPolicyRole

    def make_instance(self, **overrides):
        return HostPolicyRole.objects.create(**{"name": "lowered", "description": "d", **overrides})


class LowerCaseManagerRelatedLookupTestCase(TestCase):
    """Known gap: lowercasing doesn't follow relations to a related lowercase field."""

    @expectedFailure
    def test_related_lookup_value_lowercased(self):
        # key.split("__")[0] is "atoms" (a relation), so HostPolicyAtom.name is
        # never recognised as a lowercase field and "ATOM" isn't normalised.
        atom = HostPolicyAtom.objects.create(name="atom", description="d")
        role = HostPolicyRole.objects.create(name="role", description="d")
        role.atoms.add(atom)
        self.assertTrue(HostPolicyRole.objects.filter(atoms__name="ATOM").exists())


class LowerCaseManagerCoverageTestCase(TestCase):
    def test_all_models_covered(self):
        covered = {
            cls.model._meta.label
            for cls in LowerCaseManagerTestsMixin.__subclasses__()
        }
        all_labels = {m._meta.label for m in models_with_lowercase_manager()}
        missing = all_labels - covered
        
        # Compare to empty set - fails with a list of missing models if any are found
        self.assertEqual(
            missing,
            set(),
            "The models listed above use LowerCaseManager but have no "
            "LowerCaseManagerTestsMixin subclass. Add one for each.",
        )
