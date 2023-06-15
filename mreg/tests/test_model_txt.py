from django.test import TestCase

from mreg.models import Host, Txt

from .base import clean_and_save


class ModelTxtTestCase(TestCase):
    """This class defines the test suite for the Txt model."""

    def setUp(self):
        """Define the test client and other test variables."""
        host = Host.objects.create(name="host.example.org")
        self.txt_sample = Txt(host=host, txt="some-text")

    def test_model_can_create_txt(self):
        """Test that the model is able to create a txt entry."""
        old_count = Txt.objects.count()
        clean_and_save(self.txt_sample)
        new_count = Txt.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.txt_sample)

    def test_model_can_change_txt(self):
        """Test that the model is able to change a txt entry."""
        clean_and_save(self.txt_sample)
        new_txt = "some-new-text"
        txt_sample_id = self.txt_sample.id
        self.txt_sample.txt = new_txt
        clean_and_save(self.txt_sample)
        updated_txt = Txt.objects.get(pk=txt_sample_id).txt
        self.assertEqual(new_txt, updated_txt)

    def test_model_can_delete_txt(self):
        """Test that the model is able to delete a txt entry."""
        clean_and_save(self.txt_sample)
        old_count = Txt.objects.count()
        self.txt_sample.delete()
        new_count = Txt.objects.count()
        self.assertNotEqual(old_count, new_count)
