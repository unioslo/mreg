from django.db import models

from .fields import LowerCaseCharField


class LowerCaseManager(models.Manager):
    """A manager that lowercases all values of LowerCaseCharFields in filter/exclude/get calls."""

    @property
    def lowercase_fields(self):
        if not hasattr(self, "_lowercase_fields_cache"):
            self._lowercase_fields_cache = [
                field.name
                for field in self.model._meta.get_fields()
                if isinstance(field, LowerCaseCharField)
            ]
        return self._lowercase_fields_cache

    def _lowercase_fields(self, **kwargs):
        lower_kwargs = {}
        for key, value in kwargs.items():
            field_name = key.split("__")[0]
            if field_name in self.lowercase_fields and isinstance(value, str):
                value = value.lower()
            lower_kwargs[key] = value
        return lower_kwargs

    def filter(self, **kwargs):
        return super().filter(**self._lowercase_fields(**kwargs))

    def exclude(self, **kwargs):
        return super().exclude(**self._lowercase_fields(**kwargs))

    def get(self, **kwargs):
        return super().get(**self._lowercase_fields(**kwargs))


def lower_case_manager_factory(base_manager):
    class LowerCaseBaseManager(base_manager, LowerCaseManager):
        pass

    return LowerCaseBaseManager
