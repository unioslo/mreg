
from typing import Any, Dict
from django.db import models

from .fields import LowerCaseCharField


class LowerCaseManager(models.Manager[Any]):
    """A manager that lowercases all values of LowerCaseCharFields in filter/exclude/get calls."""

    @property
    def lowercase_fields(self):
        """A list of field names that are LowerCaseCharFields.
        
        Note: This is a cached property to avoid recalculating the list every time it is accessed.
        We are making the assumption that the model's fields do not change during runtime...
        """

        if not hasattr(self, "_lowercase_fields_cache"):
            self._lowercase_fields_cache = [
                field.name
                for field in self.model._meta.get_fields()
                if isinstance(field, LowerCaseCharField)
            ]
        return self._lowercase_fields_cache

    def _lowercase_fields(self, **kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Lowercase all values of LowerCaseCharFields in kwargs."""

        lower_kwargs: Dict[str, Any] = {}
        for key, value in kwargs.items():
            field_name = key.split("__")[0]
            if field_name in self.lowercase_fields and isinstance(value, str):
                value = value.lower()
            lower_kwargs[key] = value
        return lower_kwargs

    def filter(self, **kwargs: Dict[str, Any]):
        """Lowercase all values of LowerCaseCharFields in kwargs during filtering."""
        return super().filter(**self._lowercase_fields(**kwargs))

    def exclude(self, **kwargs: Dict[str, Any]):
        """Lowercase all values of LowerCaseCharFields in kwargs during excluding."""
        return super().exclude(**self._lowercase_fields(**kwargs))

    def get(self, **kwargs: Dict[str, Any]):
        """Lowercase all values of LowerCaseCharFields in kwargs during get."""
        return super().get(**self._lowercase_fields(**kwargs))


def lower_case_manager_factory(base_manager: type[models.Manager[Any]]):
    """A factory function to create a LowerCaseManager for a given base_manager."""

    class LowerCaseBaseManager(base_manager, LowerCaseManager):
        """A manager that lowercases all values of LowerCaseCharFields in filter/exclude/get calls."""
        pass

    return LowerCaseBaseManager
