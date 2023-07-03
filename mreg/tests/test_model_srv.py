from django.core.exceptions import ValidationError
from django.test import TestCase
from mreg.models.host import Host
from mreg.models.resource_records import Srv

from .base import clean_and_save


class ModelSrvTestCase(TestCase):
    """This class defines the test suite for the Srv model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.host_target = Host.objects.create(name="target.example.org")
        self.srv_sample = Srv(
            name="_abc._udp.example.org",
            priority=3,
            weight=1,
            port=5433,
            ttl=300,
            host=self.host_target,
        )

    def test_model_can_create_srv(self):
        """Test that the model is able to create a srv entry."""
        old_count = Srv.objects.count()
        clean_and_save(self.srv_sample)
        new_count = Srv.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.srv_sample)

    def test_can_create_various_service_names(self):
        def _create(name):
            srv = Srv(name=name, priority=3, weight=1, port=5433, host=self.host_target)
            clean_and_save(srv)

        # Two underscores in _service
        _create("_test_underscore._tls.example.org")
        # Hypen
        _create("_test_underscore-hypen._tls.example.org")
        # short serivce
        _create("_gc._tcp.example.org")

    def test_reject_various_service_names(self):
        def _create(name):
            srv = Srv(name=name, priority=3, weight=1, port=5433, host=self.host_target)
            with self.assertRaises(ValidationError):
                clean_and_save(srv)

        # Two underscores after each other
        _create("_test__underscore._tls.example.org")
        # No leading underscore
        _create("opsmissingunderscore._tls.example.org")
        # No traling underscore
        _create("_underscoreinbothends_._tls.example.org")
        # Trailing hypen
        _create("_hypten-._tls.example.org")

    def test_model_can_change_srv(self):
        """Test that the model is able to change a srv entry."""
        clean_and_save(self.srv_sample)
        new_port = 5434
        self.srv_sample.port = new_port
        clean_and_save(self.srv_sample)
        updated_port = Srv.objects.get(pk=self.srv_sample.id).port
        self.assertEqual(new_port, updated_port)

    def test_model_can_delete_srv(self):
        """Test that the model is able to delete a srv entry."""
        clean_and_save(self.srv_sample)
        old_count = Srv.objects.count()
        self.srv_sample.delete()
        new_count = Srv.objects.count()
        self.assertNotEqual(old_count, new_count)
