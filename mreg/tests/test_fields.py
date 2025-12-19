"""Tests for custom field classes in mreg.fields."""

from django.test import TestCase

from mreg.fields import (
    DnsNameField,
    LCICharField,
    LowerCaseCharField,
    LowerCaseDNSNameField,
)
from mreg.validators import validate_hostname


class LowerCaseCharFieldTest(TestCase):
    """Test LowerCaseCharField behavior."""

    def test_get_db_prep_save_with_string(self):
        """Test that string values are converted to lowercase."""
        field = LowerCaseCharField()
        result = field.get_db_prep_save("UPPERCASE", connection=None)
        self.assertEqual(result, "uppercase")

    def test_get_db_prep_save_with_non_string(self):
        """Test that non-string values are passed through unchanged."""
        field = LowerCaseCharField()
        result = field.get_db_prep_save(None, connection=None)
        self.assertIsNone(result)


class LCICharFieldTest(TestCase):
    """Test LCICharField behavior."""

    def test_get_db_prep_save_with_string(self):
        """Test that string values are converted to lowercase."""
        field = LCICharField()
        result = field.get_db_prep_save("UPPERCASE", connection=None)
        self.assertEqual(result, "uppercase")

    def test_get_db_prep_save_with_non_string(self):
        """Test that non-string values are passed through unchanged."""
        field = LCICharField()
        result = field.get_db_prep_save(None, connection=None)
        self.assertIsNone(result)


class LowerCaseDNSNameFieldTest(TestCase):
    """Test LowerCaseDNSNameField initialization and behavior."""

    def test_init_without_validators(self):
        """Test field initialization without custom validators uses default."""
        field = LowerCaseDNSNameField()
        self.assertEqual(field.max_length, 253)
        self.assertIn(validate_hostname, field.validators)

    def test_init_with_custom_validators(self):
        """Test field initialization with custom validators."""
        def custom_validator(x):
            pass
        field = LowerCaseDNSNameField(validators=[custom_validator])
        self.assertEqual(field.max_length, 253)
        self.assertIn(custom_validator, field.validators)
        # When custom validators are provided, the default is not added
        self.assertNotIn(validate_hostname, field.validators)

    def test_get_db_prep_save(self):
        """Test that DNS names are stored in lowercase."""
        field = LowerCaseDNSNameField()
        result = field.get_db_prep_save("EXAMPLE.COM", connection=None)
        self.assertEqual(result, "example.com")


class DnsNameFieldTest(TestCase):
    """Test DnsNameField initialization and behavior."""

    def test_init_without_validators(self):
        """Test field initialization without custom validators uses default."""
        field = DnsNameField()
        self.assertEqual(field.max_length, 253)
        self.assertIn(validate_hostname, field.validators)

    def test_init_with_custom_validators(self):
        """Test field initialization with custom validators."""
        def custom_validator(x):
            pass
        field = DnsNameField(validators=[custom_validator])
        self.assertEqual(field.max_length, 253)
        self.assertIn(custom_validator, field.validators)
        # When custom validators are provided, the default is not added
        self.assertNotIn(validate_hostname, field.validators)

    def test_get_db_prep_save(self):
        """Test that DNS names are stored in lowercase."""
        field = DnsNameField()
        result = field.get_db_prep_save("EXAMPLE.COM", connection=None)
        self.assertEqual(result, "example.com")
