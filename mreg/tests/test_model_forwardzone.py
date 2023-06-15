from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from mreg.models import ForwardZone, Host

from .base import clean_and_save


class ModelForwardZoneTestCase(TestCase):
    """This class defines the test suite for the ForwardZone model."""

    # TODO: test this for sub-zones (sub.example.org)
    def setUp(self):
        """Define the test client and other test variables."""
        self.zone_sample = ForwardZone(
            name="example.org",
            primary_ns="ns.example.org",
            email="hostmaster@example.org",
            serialno=1234567890,
            refresh=400,
            retry=300,
            expire=800,
            soa_ttl=300,
            default_ttl=1000,
        )

    def test_model_can_create_a_zone(self):
        """Test that the model is able to create a zone."""
        old_count = ForwardZone.objects.count()
        clean_and_save(self.zone_sample)
        new_count = ForwardZone.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.zone_sample)

    def test_model_can_change_a_zone(self):
        """Test that the model is able to change a zone."""
        clean_and_save(self.zone_sample)
        old_name = self.zone_sample.name
        new_name = "example.com"
        zone_sample_id = ForwardZone.objects.get(name=old_name).id
        self.zone_sample.name = new_name
        clean_and_save(self.zone_sample)
        updated_name = ForwardZone.objects.get(pk=zone_sample_id).name
        self.assertEqual(new_name, updated_name)

    def test_model_can_delete_a_zone(self):
        """Test that the model is able to delete a zone."""
        clean_and_save(self.zone_sample)
        old_count = ForwardZone.objects.count()
        self.zone_sample.delete()
        new_count = ForwardZone.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_update_serialno(self):
        """Force update by setting serialno_updated_at in the past"""
        zone = ForwardZone(
            name="example.org",
            primary_ns="ns.example.org",
            email="hostmaster@example.org",
        )
        zone.save()
        zone.serialno_updated_at = timezone.now() - timedelta(minutes=10)
        old_serial = zone.serialno
        zone.save()
        zone.update_serialno()
        self.assertLess(old_serial, zone.serialno)
        # Will not update serialno just becase updated = True, requires a timedelta
        old_serial = zone.serialno
        zone.updated = True
        zone.update_serialno()
        zone.save()
        zone.refresh_from_db()
        self.assertEqual(old_serial, zone.serialno)
        self.assertTrue(zone.updated)

    def test_update_serialno_wrapping(self):
        """Make sure serialno can not wrap and the zone is unchanged when hitting
        max serialnumber.
        """
        zone = ForwardZone(
            name="example.org",
            primary_ns="ns.example.org",
            email="hostmaster@example.org",
        )
        zone.serialno += 999
        zone.save()
        zone.refresh_from_db()
        # Make sure the serialno does not wrap, but instead keeps stays the same
        self.assertEqual(zone.serialno % 1000, 999)
        old_suat = zone.serialno_updated_at = timezone.now() - timedelta(minutes=10)
        zone.save()
        old_serial = zone.serialno
        zone.update_serialno()
        zone.refresh_from_db()
        self.assertTrue(zone.updated)
        self.assertEqual(old_serial, zone.serialno)
        self.assertEqual(old_suat, zone.serialno_updated_at)

    def test_update_hosts_when_zone_added(self):
        """When you add a Zone, existing Host objects that have a domain
        that matches the Zone should be put in that zone."""
        host = Host.objects.create(name="foo." + self.zone_sample.name)
        host.save()
        # Here's another host in a sub-zone, it should not be touched...
        otherhost = Host.objects.create(name="foo.bar." + self.zone_sample.name)
        otherhost.save()
        # Save the zone. This should trigger code that updates the host
        self.zone_sample.save()
        saved = Host.objects.get(name=host.name)
        self.assertNotEqual(saved.zone, None)
        self.assertEqual(saved.zone.name, self.zone_sample.name)
        # Verify that otherhost wasn't changed
        meh = Host.objects.get(name=otherhost.name)
        self.assertEqual(meh.zone, None)
