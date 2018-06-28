from django.test import TestCase
from api.models import Hosts


class ModelTestCase(TestCase):
    """This class defines the test suite for the Hosts model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.hosts_name = "dette-er-en-host"
        self.hosts = Hosts(name=self.hostname)

    def test_model_can_create_a_host(self):
        """Test that the model is able to create a host."""
        old_count = Hosts.objects.count()
        self.hosts.save()
        new_count = Hosts.objects.count()
        self.assertNotEqual(old_count, new_count)
