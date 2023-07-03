from django.test import TestCase
from mreg.models.host import Host
from mreg.models.resource_records import Naptr

from .base import clean_and_save


class ModelNaptrTestCase(TestCase):
    """This class defines the test suite for the Naptr model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host to test properly
        host = Host.objects.create(name="host.example.org")
        self.naptr_sample = Naptr(
            host=host,
            preference=1,
            order=1,
            flag="a",
            service="SER+VICE",
            regex="^naptrregex",
            replacement="some replacement",
        )

    def test_model_can_create_naptr(self):
        """Test that the model is able to create a naptr entry."""
        old_count = Naptr.objects.count()
        clean_and_save(self.naptr_sample)
        new_count = Naptr.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.naptr_sample)

    def test_model_can_change_naptr(self):
        """Test that the model is able to change a naptr entry."""
        clean_and_save(self.naptr_sample)
        new_flag = "u"
        self.naptr_sample.flag = new_flag
        clean_and_save(self.naptr_sample)
        updated_flag = Naptr.objects.get(pk=self.naptr_sample.id).flag
        self.assertEqual(new_flag, updated_flag)

    def test_model_can_delete_naptr(self):
        """Test that the model is able to delete a naptr entry."""
        clean_and_save(self.naptr_sample)
        old_count = Naptr.objects.count()
        self.naptr_sample.delete()
        new_count = Naptr.objects.count()
        self.assertNotEqual(old_count, new_count)
