"""Tests for m2m member naming in 404 messages (`mreg.utils.display_name`)."""

from abc import ABC
from collections.abc import Sequence
import importlib
import inspect
import pkgutil
from typing import TypeVar
from django.db.models import Model
from django.test import SimpleTestCase

# Import the view modules so every M2MDetail subclass is registered before we
# enumerate __subclasses__ below.
from mreg import models
from hostpolicy import models as hostpolicy_models # noqa: F401
import hostpolicy.api.v1.views  # noqa: F401
import mreg.api.v1.views_hostgroups  # noqa: F401
from mreg.api.v1.views_m2m import M2MDetail, M2MBase, M2MList
from mreg.utils import display_name

T = TypeVar("T")

def _get_concrete_subclasses(t: type[T]) -> Sequence[type[T]]:
    """Every concrete subclass of the given type."""
    subclasses: list[type[T]] = []
    stack = list(t.__subclasses__())
    while stack:
        sub = stack.pop()
        stack.extend(sub.__subclasses__())
        # NOTE: we use ABC as a hack to signal that the view
        # should not be considered a concrete subclass.
        if not inspect.isabstract(sub) and ABC not in sub.__bases__:
            subclasses.append(sub)
    return subclasses


def _get_m2m_views_with_models() -> Sequence[tuple[type[M2MDetail], type[Model]]]:
    views_with_models: list[tuple[type[M2MDetail], type[Model]]] = []
    for view in _get_concrete_subclasses(M2MDetail):
        if getattr(view, "m2m_field", None) and getattr(view, "cls", None):
            views_with_models.append((view, view.cls._meta.get_field(view.m2m_field).related_model))
    return views_with_models


class TestCaseWithModels(SimpleTestCase):
    def setUp(self):
        # import every sub-module in mreg.models so all model classes are loaded.
        for mod in pkgutil.iter_modules(models.__path__):
            importlib.import_module(f"{models.__name__}.{mod.name}")


class DisplayNameTests(TestCaseWithModels):
    def test_every_m2m_detail_subclass_has_expected_member_name(self):
        """Every concrete M2MDetail subclass maps to a known member name.

        Pins the wording of the model display name used in 404 errors with 
        explicit literals, and fails if a subclass is added or removed, 
        or a member model's `verbose_name` changes.

        `HostGroupOwnersDetail` overrides `member_not_found()` and doesn't actually use
        `display_name()`, but is listed here for completeness of the subclass set.
        """
        expected = {
            "HostPolicyRoleAtomsDetail": "Atom",
            "HostPolicyRoleHostsDetail": "Host",
            "HostGroupGroupsDetail": "Host group",
            "HostGroupHostsDetail": "Host",
            "HostGroupOwnersDetail": "Group",
        }
        for view in _get_concrete_subclasses(M2MDetail):
            with self.subTest(view=view.__name__):
                self.assertIn(view.__name__, expected)
                self.assertEqual(
                    display_name(view.cls._meta.get_field(view.m2m_field).related_model, capitalize=True),
                    expected[view.__name__],
                )
                expected.pop(view.__name__)
        self.assertFalse(expected, f"Expected views not tested: {list(expected.keys())}")


class M2MClassVarTests(TestCaseWithModels):
    """Tests for class vars in M2M views that do not directly inherit from abc.ABC"""
    def test_m2m_base_class_vars(self):
        for view in _get_concrete_subclasses(M2MBase):
            with self.subTest(view=view.__name__):
                self.assertTrue(hasattr(view, "m2m_field"))
                self.assertTrue(hasattr(view, "cls"))
                self.assertTrue(hasattr(view, "lookup_field"))
                self.assertTrue(hasattr(view, "lookup_url_kwarg"))

    def test_m2m_list_class_vars(self):
        for view in _get_concrete_subclasses(M2MList):
            self.assertTrue(hasattr(view, "m2m_object"))