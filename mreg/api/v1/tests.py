from django.test import TestCase
from mreg.models import Hosts


class ModelTestCase(TestCase):
    """This class defines the test suite for the Hosts model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.host_sample = Hosts(hostid=1,
                                 name='dette-er-en-host',
                                 ipaddress='127.0.0.1',
                                 contact='ulvik@usit.uio.no')

    def test_model_can_create_a_host(self):
        """Test that the model is able to create a host."""
        old_count = Hosts.objects.count()
        self.host_sample.save()
        new_count = Hosts.objects.count()
        self.assertNotEqual(old_count, new_count)