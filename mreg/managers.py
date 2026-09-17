
from functools import lru_cache
from typing import Any

from django.db import models
from typing_extensions import Self

from .fields import LowerCaseCharField


@lru_cache(maxsize=None)
def _lowercase_field_names(model: type[models.Model]) -> frozenset[str]:
    """Names of the model's LowerCaseCharFields.

    Cached per model class; we assume the model's fields do not change at runtime.
    """
    return frozenset(
        field.name
        for field in model._meta.get_fields()
        if isinstance(field, LowerCaseCharField) and field.name
    )


class LowerCaseQuerySet(models.QuerySet):
    """A queryset that lowercases string values targeting LowerCaseCharFields.

    Lower-casing is defined on the queryset intead of a manager, so 
    chained lookups derived from this queryset also benefit from lower-casing.
    """

    def _lowercase_fields(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        """Lowercase all values of LowerCaseCharFields in kwargs."""
        lowercase_fields = _lowercase_field_names(self.model)
        lower_kwargs: dict[str, Any] = {}
        for key, value in kwargs.items():
            field_name = key.split("__")[0]
            if field_name in lowercase_fields and isinstance(value, str):
                value = value.lower()
            lower_kwargs[key] = value
        return lower_kwargs

    def filter(self, *args: Any, **kwargs: Any) -> Self:
        return super().filter(*args, **self._lowercase_fields(kwargs))

    def exclude(self, *args: Any, **kwargs: Any) -> Self:
        return super().exclude(*args, **self._lowercase_fields(kwargs))

    def get(self, *args: Any, **kwargs: Any) -> Any:
        return super().get(*args, **self._lowercase_fields(kwargs))


class LowerCaseManager(models.Manager.from_queryset(LowerCaseQuerySet)):
    """A manager that lowercases all values of LowerCaseCharFields in filter/exclude/get calls."""
    pass


def lower_case_manager_factory(base_manager: type[models.Manager]) -> type[LowerCaseManager]:
    """A factory function to create a LowerCaseManager for a given base_manager."""

    class LowerCaseBaseManager(base_manager, LowerCaseManager):
        """A manager that lowercases all values of LowerCaseCharFields in filter/exclude/get calls."""
        pass

    return LowerCaseBaseManager
