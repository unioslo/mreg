"""Tests for m2m member naming in 404 messages (`mreg.utils.display_name`)."""

from django.test import SimpleTestCase

# Import the view modules so every M2MDetail subclass is registered before we
# enumerate __subclasses__ below.
import hostpolicy.api.v1.views  # noqa: F401
import mreg.api.v1.views_hostgroups  # noqa: F401
from hostpolicy.models import HostPolicyAtom, HostPolicyRole
from mreg.api.v1.views_m2m import M2MDetail
from mreg.models.host import Host, HostGroup
from mreg.utils import display_name


def _concrete_m2m_detail_views():
    """Every concrete M2MDetail subclass, i.e. those bound to an m2m relation."""
    views = []
    stack = list(M2MDetail.__subclasses__())
    while stack:
        view = stack.pop()
        stack.extend(view.__subclasses__())
        if getattr(view, "m2m_field", None) and getattr(view, "cls", None):
            views.append(view)
    return views


class DisplayNameTests(SimpleTestCase):

    def test_display_name(self):
        """display_name sentence-cases each model's verbose_name."""
        self.assertEqual(display_name(HostPolicyAtom), "Atom")
        self.assertEqual(display_name(HostPolicyRole), "Role")
        self.assertEqual(display_name(Host), "Host")
        self.assertEqual(display_name(HostGroup), "Host group")

    def test_every_m2m_detail_subclass_has_expected_member_name(self):
        """Every concrete M2MDetail subclass maps to a known member name.

        Pins the 404 wording with explicit literals, and fails if a subclass is
        added or removed, or a member model's verbose_name changes.

        HostGroupOwnersDetail overrides member_not_found and doesn't actually use
        display_name, but is listed here for completeness of the subclass set.
        """
        expected = {
            "HostPolicyRoleAtomsDetail": "Atom",
            "HostPolicyRoleHostsDetail": "Host",
            "HostGroupGroupsDetail": "Host group",
            "HostGroupHostsDetail": "Host",
            "HostGroupOwnersDetail": "Group",
        }
        actual = {
            view.__name__: display_name(
                view.cls._meta.get_field(view.m2m_field).related_model
            )
            for view in _concrete_m2m_detail_views()
        }
        self.assertEqual(actual, expected)
