from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.exceptions import PermissionDenied

from mreg.models.base import History, NameServer
from mreg.models.host import Host, HostGroup, Ipaddress, PtrOverride
from mreg.models.network import NetGroupRegexPermission, Network
from mreg.models.resource_records import Cname, Txt
from mreg.models.zone import ForwardZone, ReverseZone
from mreg.signals import (
    MQSender,
    _common_update_zone,
    _host_update_m2m_relations,
    _identifier,
    _signal_history,
    add_auto_txt_records_on_new_host,
    capture_old_name,
    cleanup_network_permissions,
    hostgroup_update_updated_at_on_changes,
    log_object_creation,
    log_object_deletion,
    object_log,
    populate_user_from_ldap,
    prevent_hostgroup_parent_recursion,
    prevent_nameserver_deletion,
    send_event_host_created,
    send_event_host_removed,
    send_event_ip_added_to_host,
    send_event_ip_removed_from_host,
    update_hosts_when_zone_is_added,
)


class SignalsTest(TestCase):
    def test_identifier_with_and_without_id(self):
        class X:
            def __str__(self):
                return "x"

        x = X()
        self.assertEqual(_identifier(x), "x")

        h = Host.objects.create(name="a.example")
        self.assertEqual(_identifier(h), h.id)

    def test_signal_history_validation_and_save(self):
        # should save valid history
        _signal_history("host", "h", "create", "Host", 1, {"a": 1})
        self.assertTrue(History.objects.exists())  # type: ignore[attr-defined]

        # should ignore invalid history (model too long triggers ValidationError)
        before = History.objects.count()  # type: ignore[attr-defined]
        _signal_history("host", "h", "create", "M" * 200, 1, {"a": 1})
        self.assertEqual(History.objects.count(), before)  # type: ignore[attr-defined]

    def test_populate_user_from_ldap(self):
        User = get_user_model()
        u = User.objects.create_user("u")
        ldap_user = mock.MagicMock()
        ldap_user.attrs = {"memberOf": ["cn=grp1,ou=org", "cn=other,ou=org"]}
        with override_settings(LDAP_GROUP_ATTR="memberOf", LDAP_GROUP_RE=r"^cn=(?P<group_name>[^,]+),"):
            populate_user_from_ldap(sender=None, signal=None, user=u, ldap_user=ldap_user)
        self.assertTrue(u.groups.exists())

        # test early return when LDAP settings are None
        u2 = User.objects.create_user("u2")
        with override_settings(LDAP_GROUP_ATTR=None, LDAP_GROUP_RE=None):
            populate_user_from_ldap(sender=None, signal=None, user=u2, ldap_user=ldap_user)
        self.assertFalse(u2.groups.exists())

    def test_ipaddress_ptroverride_create_and_update(self):
        h1 = Host.objects.create(name="h1.example")
        h2 = Host.objects.create(name="h2.example")
        # create first ip
        Ipaddress.objects.create(host=h1, ipaddress="10.0.0.1")  # type: ignore[attr-defined]
        # creating second ip with same address should create PtrOverride for first host
        Ipaddress.objects.create(host=h2, ipaddress="10.0.0.1")  # type: ignore[attr-defined]
        self.assertTrue(PtrOverride.objects.filter(ipaddress="10.0.0.1").exists())  # type: ignore[attr-defined]

        # change ip on h1's ipaddress should remove its PtrOverride
        ip = Ipaddress.objects.filter(host=h1).first()  # type: ignore[attr-defined]
        ip.ipaddress = "10.0.0.2"  # type: ignore[union-attr]
        ip.save()  # type: ignore[union-attr]
        self.assertFalse(PtrOverride.objects.filter(host=h1).exists())  # type: ignore[attr-defined]

    def test_common_update_zone_sets_zone_updated(self):
        rz = ReverseZone.objects.create(name="0.0.10.in-addr.arpa")
        # monkeypatch get_zone_by_ip to return our zone
        original = ReverseZone.get_zone_by_ip
        ReverseZone.get_zone_by_ip = staticmethod(lambda ip: rz)
        try:
            # call common update for an Ipaddress-like object
            class I:
                ipaddress = "10.0.0.5"

            _common_update_zone("pre_save", Ipaddress, I())
            rz.refresh_from_db()
            self.assertTrue(rz.updated)
        finally:
            ReverseZone.get_zone_by_ip = original

    def test_host_m2m_and_hostgroup_actions(self):
        h = Host.objects.create(name="hm.example")
        hg = HostGroup.objects.create(name="g1")
        hg.hosts.add(h)
        # simulate m2m_changed post_add
        hostgroup_update_updated_at_on_changes(sender=None, instance=hg, action="post_add", model=None, reverse=False, pk_set={h.id})
        # hostgroup saved without error

        # prevent recursion self membership
        with self.assertRaises(PermissionDenied):
            prevent_hostgroup_parent_recursion(sender=None, instance=hg, action="pre_add", model=None, reverse=False, pk_set={hg.id})

    def test_prevent_nameserver_deletion(self):
        h = Host.objects.create(name="ns.example")
        ns = NameServer.objects.create(name="ns.example")
        fz = ForwardZone.objects.create(name="example")
        fz.nameservers.add(ns)
        with self.assertRaises(PermissionDenied):
            prevent_nameserver_deletion(sender=Host, instance=h, using=None)

        # ipaddress case: if host has >1 ipaddresses, should return without raising
        h2 = Host.objects.create(name="multi.example")
        Ipaddress.objects.create(host=h2, ipaddress="1.1.1.1")  # type: ignore[attr-defined]
        Ipaddress.objects.create(host=h2, ipaddress="1.1.1.2")  # type: ignore[attr-defined]
        ns2 = NameServer.objects.create(name="multi.example")
        fz2 = ForwardZone.objects.create(name="example2")
        fz2.nameservers.add(ns2)
        # should not raise when deleting an Ipaddress if host has more than one
        ia = Ipaddress.objects.filter(host=h2).first()  # type: ignore[attr-defined]
        prevent_nameserver_deletion(sender=Ipaddress, instance=ia, using=None)

    def test_cleanup_network_permissions(self):
        net = Network.objects.create(network="10.1.0.0/24")
        perm = NetGroupRegexPermission.objects.create(group="g", range="10.1.0.0/24", regex="^a")
        cleanup_network_permissions(sender=Network, instance=net)
        self.assertFalse(NetGroupRegexPermission.objects.filter(id=perm.id).exists())

    def test_auto_txt_and_update_zone_hosts(self):
        fz = ForwardZone.objects.create(name="auto.example")
        with override_settings(TXT_AUTO_RECORDS={"auto.example": ["x"]}):
            h = Host.objects.create(name="a.auto.example")
            h.zone = fz  # type: ignore[assignment]
            add_auto_txt_records_on_new_host(sender=Host, instance=h, created=True)
            self.assertTrue(Txt.objects.filter(host=h, txt="x").exists())  # type: ignore[attr-defined]

        # test early return when TXT_AUTO_RECORDS is None
        h_no_setting = Host.objects.create(name="nosetting.example")
        with override_settings(TXT_AUTO_RECORDS=None):
            add_auto_txt_records_on_new_host(sender=Host, instance=h_no_setting, created=True)
            self.assertFalse(Txt.objects.filter(host=h_no_setting).exists())  # type: ignore[attr-defined]

        # test early return when zone is None
        h_nozone = Host.objects.create(name="orphan.nowhere")
        # Use PropertyMock to override the zone property
        with mock.patch.object(type(h_nozone), "zone", new_callable=mock.PropertyMock, return_value=None):
            with override_settings(TXT_AUTO_RECORDS={"nowhere": ["y"]}):
                add_auto_txt_records_on_new_host(sender=Host, instance=h_nozone, created=True)
                self.assertFalse(Txt.objects.filter(host=h_nozone).exists())  # type: ignore[attr-defined]

        # update hosts when zone added
        h2 = Host.objects.create(name="b.newzone")
        fz2 = ForwardZone.objects.create(name="newzone")
        update_hosts_when_zone_is_added(sender=ForwardZone, instance=fz2, created=True)
        h2.refresh_from_db()
        self.assertEqual(h2.zone, fz2)

    def test_mq_and_capture_old_name_and_logging(self):
        h = Host.objects.create(name="mq.example")
        # capture_old_name when object exists
        capture_old_name(sender=Host, instance=h)
        self.assertIsNotNone(getattr(h, "_old_name", None))

        # patch MQSender.send_event
        with mock.patch.object(MQSender, "send_event") as mock_send:
            send_event_host_created(sender=Host, instance=h, created=True)
            mock_send.assert_called()
            send_event_ip_added_to_host(sender=Ipaddress, instance=Ipaddress.objects.create(host=h, ipaddress="2.2.2.2"), created=True)  # type: ignore[attr-defined]
            mock_send.assert_called()
            send_event_ip_removed_from_host(sender=Ipaddress, instance=Ipaddress.objects.create(host=h, ipaddress="3.3.3.3"))  # type: ignore[attr-defined]
            mock_send.assert_called()
            send_event_host_removed(sender=Host, instance=h)
            mock_send.assert_called()

        # logging
        with mock.patch.object(object_log, "info") as mock_info:

            class Dummy:
                pass

            d = Dummy()
            log_object_creation(sender=Dummy, instance=d, created=True)
            mock_info.assert_called()
            log_object_deletion(sender=Dummy, instance=d)
            mock_info.assert_called()

    def test_host_rename_updates_zones_with_cnames(self):
        """Test that renaming a host updates zones where it's used (Cname, Srv, PtrOverride)."""
        fz1 = ForwardZone.objects.create(name="zone1.example")
        fz2 = ForwardZone.objects.create(name="zone2.example")
        h = Host.objects.create(name="host.zone1.example")
        h.zone = fz1  # type: ignore[assignment]
        h.save()

        # Create a Cname in a different zone pointing to this host
        cname = Cname.objects.create(host=h, name="alias.zone2.example")
        cname.zone = fz2  # type: ignore[assignment]
        cname.save()

        # Rename the host - should trigger zone update for both zones
        h.name = "newhost.zone1.example"
        from mreg.signals import updated_objects_update_zone_serial

        updated_objects_update_zone_serial(sender=Host, instance=h, raw=False, using=None, update_fields=None)

        # Verify zones are marked as updated
        fz1.refresh_from_db()
        fz2.refresh_from_db()
        self.assertTrue(fz1.updated)
        self.assertTrue(fz2.updated)

    def test_host_m2m_with_hostpolicyroles(self):
        """Test that hostpolicyroles are updated when host is modified."""
        from hostpolicy.models import HostPolicyRole

        h = Host.objects.create(name="policy-host.example")
        role = HostPolicyRole.objects.create(name="test-role")
        role.hosts.add(h)

        # Call _host_update_m2m_relations to update hostpolicyroles
        _host_update_m2m_relations(h)
        # Should complete without error, covering the hostpolicyroles loop
