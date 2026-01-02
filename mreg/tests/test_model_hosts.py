from django.core.exceptions import ValidationError
from django.test import TestCase
from mreg.models.host import Host

from .base import clean_and_save


class ModelHostsTestCase(TestCase):
    """This class defines the test suite for the Host model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.host_one = Host(
            name="host.example.org",
            ttl=300,
            comment="some comment",
        )

    def assert_validation_error(self, obj):
        with self.assertRaises(ValidationError):
            obj.full_clean()

    def test_model_can_create_a_host(self):
        """Test that the model is able to create a host."""
        old_count = Host.objects.count()
        clean_and_save(self.host_one)
        new_count = Host.objects.count()
        self.assertLess(old_count, new_count)
        str(self.host_one)

    def test_model_can_create_without_contact(self):
        old_count = Host.objects.count()
        host = Host(name="host2.example.org")
        clean_and_save(host)
        new_count = Host.objects.count()
        self.assertLess(old_count, new_count)

    def test_can_create_wildcard_host(self):
        Host(name="*.example.org").full_clean()
        Host(name="*.sub.example.org").full_clean()

    def test_model_case_insesitive(self):
        """Hosts names must be case insensitive"""
        clean_and_save(self.host_one)
        self.assertEqual(
            self.host_one, Host.objects.get(name=self.host_one.name.upper())
        )
        upper = Host(name=self.host_one.name.upper())
        with self.assertRaises(ValidationError) as context:
            clean_and_save(upper)
        self.assertEqual(
            context.exception.messages, ["Host with this Name already exists."]
        )
        hostname = "UPPERCASE.EXAMPLE.ORG"
        host = Host.objects.create(name=hostname)
        # Must do a refresh_from_db() as host.name is otherwise the unmodfied
        # uppercase hostname.
        host.refresh_from_db()
        self.assertEqual(host.name, hostname.lower())

    def test_reject_bad_host_names(self):
        def _assert(hostname):
            host = Host(name=hostname)
            self.assert_validation_error(host)

        _assert("host..example.org")
        _assert("host.example.org.")
        _assert("host-.example.org")
        _assert(
            "looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong.example.org"
        )
        _assert("host*.example.org")
        _assert("host--1.example.org")

    def test_model_can_change_a_host(self):
        """Test that the model is able to change a host."""
        clean_and_save(self.host_one)
        old_name = self.host_one.name
        new_name = "some-new-host.example.org"
        host_sample_id = Host.objects.get(name=old_name).id
        self.host_one.name = new_name
        clean_and_save(self.host_one)
        updated_name = Host.objects.get(pk=host_sample_id).name
        self.assertEqual(new_name, updated_name)

    def test_model_can_delete_a_host(self):
        """Test that the model is able to delete a host."""
        clean_and_save(self.host_one)
        old_count = Host.objects.count()
        self.host_one.delete()
        new_count = Host.objects.count()
        self.assertNotEqual(old_count, new_count)
