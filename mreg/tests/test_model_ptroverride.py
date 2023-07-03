from django.core.exceptions import ValidationError
from django.test import TestCase
from mreg.models.host import Host, Ipaddress, PtrOverride

from .base import clean_and_save


class ModelPtrOverrideTestCase(TestCase):
    """This class defines the test suite for the PtrOverride model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host to test
        self.host_one = Host.objects.create(name="host1.example.org")
        self.host_two = Host.objects.create(name="host2.example.org")

        self.ptr_sample = PtrOverride(host=self.host_one, ipaddress="10.0.0.2")
        self.ptr_ipv6_sample = PtrOverride(
            host=self.host_one, ipaddress="2001:db8::beef"
        )

    def test_model_can_create_ptr(self):
        """Test that the model is able to create a PTR Override."""
        old_count = PtrOverride.objects.count()
        clean_and_save(self.ptr_sample)
        new_count = PtrOverride.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.ptr_sample)

    def test_model_can_create_ipv6_ptr(self):
        """Test that the model is able to create an IPv6 PTR Override."""
        old_count = PtrOverride.objects.count()
        clean_and_save(self.ptr_ipv6_sample)
        new_count = PtrOverride.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_reject_invalid_create_ptr(self):
        """Test that the model rejects invalid ipaddress."""
        ptr = PtrOverride(host=self.host_one, ipaddress="10.0.0.0.400")
        with self.assertRaises(ValidationError):
            ptr.full_clean()
        ptr = PtrOverride(host=self.host_one, ipaddress="10.0.0.400")
        with self.assertRaises(ValidationError):
            ptr.full_clean()

    def test_model_reject_invalid_ipv6_create_ptr(self):
        """Test that the model rejects invalid ipaddress."""
        ptr = PtrOverride(host=self.host_one, ipaddress="2001:db8::::1")
        with self.assertRaises(ValidationError):
            ptr.full_clean()
        ptr = PtrOverride(host=self.host_one, ipaddress="2001:db8::abcx")
        with self.assertRaises(ValidationError):
            ptr.full_clean()

    def test_model_can_change_ptr(self):
        """Test that the model is able to change a PTR Override."""
        clean_and_save(self.ptr_sample)
        new_ptr = "10.0.0.3"
        self.ptr_sample.ipaddress = new_ptr
        clean_and_save(self.ptr_sample)
        self.ptr_sample.refresh_from_db()
        self.assertEqual(new_ptr, self.ptr_sample.ipaddress)

    def test_model_can_change_ipv6_ptr(self):
        """Test that the model is able to change an IPv6 PTR Override."""
        clean_and_save(self.ptr_ipv6_sample)
        new_ipv6_ptr = "2011:db8::feed"
        self.ptr_ipv6_sample.ipaddress = new_ipv6_ptr
        clean_and_save(self.ptr_ipv6_sample)
        self.ptr_ipv6_sample.refresh_from_db()
        self.assertEqual(new_ipv6_ptr, self.ptr_ipv6_sample.ipaddress)

    def test_model_can_delete_ptr(self):
        """Test that the model is able to delete a PTR Override."""
        clean_and_save(self.ptr_sample)
        old_count = PtrOverride.objects.count()
        self.ptr_sample.delete()
        new_count = PtrOverride.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_delete_ipv6_ptr(self):
        """Test that the model is able to delete an IPv6 PTR Override."""
        clean_and_save(self.ptr_ipv6_sample)
        old_count = PtrOverride.objects.count()
        self.ptr_ipv6_sample.delete()
        new_count = PtrOverride.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_updated_by_added_ip(self):
        """Test to check that an PtrOverride is added when two hosts share the same ip.
        Also makes sure that the PtrOverride points to the first host which held the ip.
        """
        initial_count = PtrOverride.objects.count()
        ip_one = Ipaddress(host=self.host_one, ipaddress="10.0.0.1")
        clean_and_save(ip_one)
        one_count = PtrOverride.objects.count()
        ip_two = Ipaddress(host=self.host_two, ipaddress="10.0.0.1")
        clean_and_save(ip_two)
        ptr = PtrOverride.objects.first()
        self.assertEqual(ptr.host, self.host_one)
        self.assertEqual(ptr.ipaddress, "10.0.0.1")
        self.assertEqual(initial_count, 0)
        self.assertEqual(initial_count, one_count)
        self.assertEqual(PtrOverride.objects.count(), 1)

    def test_model_updated_by_added_ipv6(self):
        """Test to check that an PtrOverride is added when two hosts share the
        same ipv6.  Also makes sure that the PtrOverride points to the first
        host which held the ipv6."""

        initial_count = PtrOverride.objects.count()
        ipv6_one = Ipaddress(host=self.host_one, ipaddress="2001:db8::4")
        clean_and_save(ipv6_one)
        one_count = PtrOverride.objects.count()
        ipv6_two = Ipaddress(host=self.host_two, ipaddress="2001:db8::4")
        clean_and_save(ipv6_two)
        ptr = PtrOverride.objects.first()
        self.assertEqual(ptr.host, self.host_one)
        self.assertEqual(ptr.ipaddress, "2001:db8::4")
        self.assertEqual(initial_count, 0)
        self.assertEqual(initial_count, one_count)
        self.assertEqual(PtrOverride.objects.count(), 1)

    def test_model_add_and_remove_ip(self):
        """Test to check that an PtrOverride is added when two hosts share the same ip.
        Also makes sure that the PtrOverride points to the first host which held the ip.
        Also makes sure that the PtrOverride is deleted when the host is deleted."""
        initial_count = PtrOverride.objects.count()
        Ipaddress.objects.create(host=self.host_one, ipaddress="10.0.0.1")
        one_count = PtrOverride.objects.count()
        Ipaddress.objects.create(host=self.host_two, ipaddress="10.0.0.1")
        two_count = PtrOverride.objects.count()
        ptr = PtrOverride.objects.first()
        self.assertEqual(ptr.host, self.host_one)
        self.assertEqual(ptr.ipaddress, "10.0.0.1")
        self.assertEqual(initial_count, 0)
        self.assertEqual(initial_count, one_count)
        self.assertEqual(two_count, 1)
        self.host_two.delete()
        self.assertEqual(PtrOverride.objects.count(), 1)
        self.host_one.delete()
        self.assertEqual(PtrOverride.objects.count(), 0)

    def test_model_add_and_remove_ipv6(self):
        """Test to check that an PtrOverride is added when two hosts share the same ipv6.
        Also makes sure that the PtrOverride points to the first host which held the ipv6.
        Also makes sure that the PtrOverride is deleted when the host is deleted."""
        initial_count = PtrOverride.objects.count()
        Ipaddress.objects.create(host=self.host_one, ipaddress="2001:db8::4")
        one_count = PtrOverride.objects.count()
        Ipaddress.objects.create(host=self.host_two, ipaddress="2001:db8::4")
        two_count = PtrOverride.objects.count()
        ptr = PtrOverride.objects.first()
        self.assertEqual(ptr.host, self.host_one)
        self.assertEqual(ptr.ipaddress, "2001:db8::4")
        self.assertEqual(initial_count, 0)
        self.assertEqual(initial_count, one_count)
        self.assertEqual(two_count, 1)
        self.host_one.delete()
        self.assertEqual(PtrOverride.objects.count(), 0)

    def test_model_two_ips_no_ptroverrides(self):
        """When three or more hosts all have the same ipaddress and the first host,
        e.g. the one with the PtrOverride, is deleted, a new PtrOverride is
        not created automatically.
        """

        def _add_ip(host, ipaddress):
            Ipaddress.objects.create(host=host, ipaddress=ipaddress)

        _add_ip(self.host_one, "10.0.0.1")
        _add_ip(self.host_two, "10.0.0.1")
        host_three = Host.objects.create(name="host3.example.org")
        _add_ip(host_three, "10.0.0.1")
        self.host_one.delete()
        self.assertEqual(PtrOverride.objects.count(), 0)
        self.assertEqual(Ipaddress.objects.filter(ipaddress="10.0.0.1").count(), 2)

    def test_model_two_ipv6s_no_ptroverrides(self):
        """When three or more hosts all have the same IPv6 address and the first host,
        e.g. the one with the PtrOverride, is deleted, a new PtrOverride is
        not created automatically.
        """

        def _add_ip(host, ipaddress):
            Ipaddress.objects.create(host=host, ipaddress=ipaddress)

        _add_ip(self.host_one, "2001:db8::4")
        _add_ip(self.host_two, "2001:db8::4")
        host_three = Host.objects.create(name="host3.example.org")
        _add_ip(host_three, "2001:db8::4")
        self.host_one.delete()
        self.assertEqual(PtrOverride.objects.count(), 0)
        self.assertEqual(Ipaddress.objects.filter(ipaddress="2001:db8::4").count(), 2)

    def test_ptr_not_removed_on_ipaddress_object_change(self):
        """Make sure the PtrOverride is not removed when an Ipaddress is changed, e.g.
        updated mac address."""
        ip1 = Ipaddress.objects.create(host=self.host_one, ipaddress="10.0.0.1")
        Ipaddress.objects.create(host=self.host_two, ipaddress="10.0.0.1")
        ip1.macaddress = "aa:bb:cc:dd:ee:ff"
        ip1.save()
        self.assertEqual(PtrOverride.objects.count(), 1)
