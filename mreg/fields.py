import django.contrib.postgres.fields as pgfields
import django.db.models as models

from .lookups import LOWERCASE_LOOKUPS
from .validators import validate_hostname

class LowerCaseCharField(models.CharField):
    """Store lowercase text and normalize literal values in text lookups."""

    def pre_save(self, model_instance, add):
        # Write the lowercased value back so the instance (and serializer.data) matches the DB.
        value = super().pre_save(model_instance, add)
        if isinstance(value, str):
            value = value.lower()
            setattr(model_instance, self.attname, value)
        return value

    # QuerySet.update() bypasses pre_save, so we lowercase the value here as well.
    def get_db_prep_save(self, value, connection):
        if isinstance(value, str):
            value = value.lower()
        return super().get_db_prep_save(value, connection)


for lookup in LOWERCASE_LOOKUPS:
    LowerCaseCharField.register_lookup(lookup)


class LCICharField(pgfields.CICharField):
    """A pgfields.CICharField where the value is stored in lower case.  """

    def pre_save(self, model_instance, add):
        value = super().pre_save(model_instance, add)
        if isinstance(value, str):
            value = value.lower()
            setattr(model_instance, self.attname, value)
        return value

    def get_db_prep_save(self, value, connection):
        if isinstance(value, str):
            value = value.lower()
        return super().get_db_prep_save(value, connection)

class LowerCaseDNSNameField(LowerCaseCharField):
    """A field to hold DNS names."""
    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = 253
        if 'validators' not in kwargs:
            kwargs['validators'] = [validate_hostname]
        super().__init__(*args, **kwargs)

class DnsNameField(LCICharField):
    """
    A field to hold DNS names.

    It is stored all lower case and matching is done case insensitive.
    """
    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = 253
        if 'validators' not in kwargs:
            kwargs['validators'] = [validate_hostname]
        super().__init__(*args, **kwargs)
