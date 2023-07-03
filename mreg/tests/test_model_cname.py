from django.test import TestCase
from mreg.models.host import Host
from mreg.models.resource_records import Cname

from .base import clean_and_save


class ModelCnameTestCase(TestCase):
    """This class defines the test suite for the Cname model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host to test properly
        host = Host.objects.create(name="host.example.org")
        self.cname_sample = Cname(host=host, name="some-cname.example.org", ttl=300)

    def test_model_can_create_cname(self):
        """Test that the model is able to create a cname entry."""
        old_count = Cname.objects.count()
        clean_and_save(self.cname_sample)
        new_count = Cname.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.cname_sample)

    def test_model_can_change_cname(self):
        """Test that the model is able to change a cname entry."""
        clean_and_save(self.cname_sample)
        new_cname = "some-new-cname.example.org"
        self.cname_sample.name = new_cname
        clean_and_save(self.cname_sample)
        updated_cname = Cname.objects.filter(host__name="host.example.org")[0].name
        self.assertEqual(new_cname, updated_cname)

    def test_model_can_delete_cname(self):
        """Test that the model is able to delete a cname entry."""
        clean_and_save(self.cname_sample)
        old_count = Cname.objects.count()
        self.cname_sample.delete()
        new_count = Cname.objects.count()
        self.assertNotEqual(old_count, new_count)
