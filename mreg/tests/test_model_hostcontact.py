from django.core.exceptions import ValidationError
from django.test import TestCase
from unittest_parametrize import ParametrizedTestCase, parametrize, param

from mreg.models.host import Host, HostContact

from .base import clean_and_save


class ModelHostContactTestCase(TestCase):
    """This class defines the test suite for the HostContact model."""

    def test_model_can_create_valid_contact(self):
        """Test that the model can create a contact with a valid email."""
        old_count = HostContact.objects.count()
        contact = HostContact(email="valid@example.org")
        clean_and_save(contact)
        new_count = HostContact.objects.count()
        self.assertLess(old_count, new_count)
        self.assertEqual(str(contact), "valid@example.org")

    def test_model_rejects_invalid_email_on_full_clean(self):
        """Test that full_clean() rejects invalid email addresses."""
        contact = HostContact(email="not an email")
        with self.assertRaises(ValidationError) as context:
            contact.full_clean()
        self.assertIn('email', context.exception.error_dict) # type: ignore

    def test_model_rejects_invalid_email_on_save(self):
        """Test that save() automatically validates and rejects invalid emails."""
        contact = HostContact(email="invalid email address")
        with self.assertRaises(ValidationError) as context:
            contact.save()
        self.assertIn('email', context.exception.error_dict) # type: ignore

    def test_model_rejects_invalid_email_on_create(self):
        """Test that create() validates and rejects invalid emails."""
        with self.assertRaises(ValidationError) as context:
            HostContact.objects.create(email="bad@email")
        self.assertIn('email', context.exception.error_dict) # type: ignore

    def test_model_rejects_invalid_email_on_get_or_create(self):
        """Test that get_or_create() validates and rejects invalid emails."""
        with self.assertRaises(ValidationError) as context:
            HostContact.objects.get_or_create(email="spaces in email")
        self.assertIn('email', context.exception.error_dict) # type: ignore

    def test_can_retrieve_contact_by_email(self):
        """Test that we can retrieve a contact by email address."""
        email = "retrieval-test@example.org"
        HostContact.objects.create(email=email)
        retrieved = HostContact.objects.get(email=email)
        self.assertEqual(retrieved.email, email)

    def test_duplicate_emails_are_prevented(self):
        """Test that duplicate email addresses are prevented by unique constraint."""
        email = "duplicate@example.org"
        HostContact.objects.create(email=email)
        # Attempting to create another contact with same email should fail
        with self.assertRaises(Exception):  # Django will raise IntegrityError
            HostContact.objects.create(email=email)

    def test_email_reuse_across_hosts(self):
        """Test that the same email can be reused across multiple hosts."""
        host1 = Host.objects.create(name="host1.example.org")
        host2 = Host.objects.create(name="host2.example.org")
        email = "shared@example.org"
        
        # Add same email to both hosts
        contact1, created1 = host1._add_contact(email)
        contact2, created2 = host2._add_contact(email)
        
        # Should reuse the same contact instance
        self.assertEqual(contact1.id, contact2.id) # type: ignore[attribute-defined]
        self.assertTrue(created1)  # Association created for host1
        self.assertTrue(created2)  # Association created for host2 (different from host1)
        
        # Verify only one HostContact exists
        self.assertEqual(HostContact.objects.filter(email=email).count(), 1)
        
        # Verify both hosts have this contact
        self.assertIn(contact1, host1.contacts.all())
        self.assertIn(contact1, host2.contacts.all())

    def test_orphaned_contact_cleanup(self):
        """Test that orphaned contacts are cleaned up when no hosts reference them."""
        host = Host.objects.create(name="cleanup-test.example.org")
        email = "orphan@example.org"
        
        contact, _ = host._add_contact(email)
        contact_id = contact.id # type: ignore[attribute-defined]
        
        # Verify contact exists
        self.assertEqual(HostContact.objects.filter(id=contact_id).count(), 1)
        
        # Remove contact from host
        host.contacts.remove(contact)
        
        # After signal processing, orphaned contact should be removed
        self.assertEqual(HostContact.objects.filter(id=contact_id).count(), 0)

    def test_contact_persists_when_shared(self):
        """Test that a contact is not deleted if it's still used by other hosts."""
        host1 = Host.objects.create(name="persist1.example.org")
        host2 = Host.objects.create(name="persist2.example.org")
        email = "persistent@example.org"
        
        contact, _ = host1._add_contact(email)
        host2._add_contact(email)
        contact_id = contact.id # type: ignore[attribute-defined]
        
        # Remove from first host
        host1.contacts.remove(contact)
        
        # Contact should still exist because host2 uses it
        self.assertEqual(HostContact.objects.filter(id=contact_id).count(), 1)
        self.assertIn(contact, host2.contacts.all())

    def test_contact_cleanup_on_host_deletion(self):
        """Test that orphaned contacts are cleaned up when a host is deleted."""
        host = Host.objects.create(name="delete-test.example.org")
        email = "delete-orphan@example.org"
        
        contact, _ = host._add_contact(email)
        contact_id = contact.id # type: ignore[attribute-defined]
        
        # Delete the host
        host.delete()
        
        # Contact should be removed as it's now orphaned
        self.assertEqual(HostContact.objects.filter(id=contact_id).count(), 0)

    def test_contact_persists_after_host_deletion_if_shared(self):
        """Test that contact persists after deleting one host if other hosts still use it."""
        host1 = Host.objects.create(name="keep1.example.org")
        host2 = Host.objects.create(name="keep2.example.org")
        email = "keep@example.org"
        
        contact, _ = host1._add_contact(email)
        host2._add_contact(email)
        contact_id = contact.id # type: ignore[attribute-defined]
        
        # Delete first host
        host1.delete()
        
        # Contact should still exist because host2 uses it
        self.assertEqual(HostContact.objects.filter(id=contact_id).count(), 1)
        self.assertIn(contact, host2.contacts.all())

    def test_cleanup_orphaned_contacts_method(self):
        """Test the cleanup_orphaned_contacts() class method."""
        # Create orphaned contacts directly without adding to host
        contact1 = HostContact.objects.create(email="orphan1@example.org")
        contact2 = HostContact.objects.create(email="orphan2@example.org")
        
        # Verify they exist
        self.assertTrue(HostContact.objects.filter(id=contact1.id).exists()) # type: ignore[attribute-defined]
        self.assertTrue(HostContact.objects.filter(id=contact2.id).exists()) # type: ignore[attribute-defined]
        
        # Manually run cleanup
        removed_count = HostContact.cleanup_orphaned_contacts()
        
        # Should have removed 2 orphaned contacts
        self.assertEqual(removed_count, 2)
        self.assertFalse(HostContact.objects.filter(id=contact1.id).exists()) # type: ignore[attribute-defined]
        self.assertFalse(HostContact.objects.filter(id=contact2.id).exists()) # type: ignore[attribute-defined]


class ModelHostContactValidEmailsTestCase(ParametrizedTestCase, TestCase):
    """Parameterized tests for valid email addresses."""

    @parametrize(
        ("email",),
        [
            param("simple@example.org"),
            param("user+tag@example.com"),
            param("user.name@example.org"),
            param("user_name@example.org"),
            param("123@example.org"),
            param("a@example.org"),
            param("user-name@example.org"),
            param("first.last@sub.example.org"),
            param("test+filter@mail.example.com"),
        ],
    )
    def test_model_accepts_valid_email(self, email: str):
        """Test that valid email formats are accepted."""
        contact = HostContact(email=email)
        clean_and_save(contact)
        self.assertEqual(contact.email, email)


class ModelHostContactInvalidEmailsTestCase(ParametrizedTestCase, TestCase):
    """Parameterized tests for invalid email addresses."""

    @parametrize(
        ("email",),
        [
            param("not an email"),
            param("missing@domain"),
            param("@example.org"),
            param("missing-at-sign.org"),
            param("spaces in@email.org"),
            param("double@@example.org"),
            param("trailing-dot@example.org."),
            param(""),
            param("no-domain@"),
            param("missing-tld@domain"),
            param("user name@example.org"),
            param("user@domain with space.org"),
        ],
    )
    def test_model_rejects_invalid_email(self, email: str):
        """Test that invalid email formats are rejected."""
        contact = HostContact(email=email)
        with self.assertRaises(ValidationError):
            contact.save()
