from django.test import TestCase

from mreg.models import Host, Sshfp

from .base import clean_and_save


class ModelSshfpTestCase(TestCase):
    """This class defines the test suite for the Sshfp model."""

    def setUp(self):
        """Define the test client and other test variables."""
        host = Host.objects.create(name="host.example.org")
        self.sshfp_sample = Sshfp(
            host=host, algorithm=1, hash_type=1, fingerprint="01234567890abcdef"
        )

    def test_model_can_create_sshfp(self):
        """Test that the model is able to create an sshfp entry."""
        old_count = Sshfp.objects.count()
        clean_and_save(self.sshfp_sample)
        new_count = Sshfp.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.sshfp_sample)

    def test_model_can_change_sshfp(self):
        """Test that the model is able to change an sshfp entry."""
        clean_and_save(self.sshfp_sample)
        new_fingerprint = "fedcba9876543210"
        sshfp_sample_id = self.sshfp_sample.id
        self.sshfp_sample.fingerprint = new_fingerprint
        clean_and_save(self.sshfp_sample)
        updated_fingerprint = Sshfp.objects.get(pk=sshfp_sample_id).fingerprint
        self.assertEqual(new_fingerprint, updated_fingerprint)

    def test_model_can_delete_sshfp(self):
        """Test that the model is able to delete an sshfp entry."""
        clean_and_save(self.sshfp_sample)
        old_count = Sshfp.objects.count()
        self.sshfp_sample.delete()
        new_count = Sshfp.objects.count()
        self.assertNotEqual(old_count, new_count)
