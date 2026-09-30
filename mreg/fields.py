import django.contrib.postgres.fields as pgfields
import django.db.models as models

from .lookups import LOWERCASE_LOOKUPS
from .validators import validate_hostname

class LowerCaseCharField(models.CharField):
    """Store lowercase text and normalize literal values in text lookups."""

    def get_db_prep_save(self, value, connection):
        if isinstance(value, str):
            value = value.lower()
        return super().get_db_prep_save(value, connection)


for lookup in LOWERCASE_LOOKUPS:
    LowerCaseCharField.register_lookup(lookup)


class LCICharField(pgfields.CICharField):
    """A pgfields.CICharField where the value is stored in lower case.  """

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
