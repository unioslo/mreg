"""Snapshot tests for model display/verbose names, and their interaction
with their `display_name()` representations.
"""

from django.apps import apps
from django.db.models import Model

from mreg.utils import display_name

MODELS: list[Model] = sorted(
    (m for m in apps.get_models() if m._meta.app_label in {"mreg", "hostpolicy"}),
    key=lambda m: (m._meta.app_label, m.__name__),
)
"""All models in both the mreg and hostpolicy apps."""


def test_display_name_snapshot(snapshot):
    """Snapshot test for model display names."""
    result = {
        f"{m._meta.app_label}.{m.__name__}": display_name(m) for m in MODELS
    }
    assert result == snapshot

def test_display_name_capitalize_snapshot(snapshot):
    """Snapshot test for model display names."""
    result = {
        f"{m._meta.app_label}.{m.__name__}": display_name(m, capitalize=True) for m in MODELS
    }
    assert result == snapshot


def test_verbose_name_snapshot(snapshot):
    """Snapshot test for the verbose names of models."""
    result = {
        f"{m._meta.app_label}.{m.__name__}": {
            "verbose_name": str(m._meta.verbose_name),
            "verbose_name_plural": str(m._meta.verbose_name_plural),
        }
        for m in MODELS
    }
    assert result == snapshot
