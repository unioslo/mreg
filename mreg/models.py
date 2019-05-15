import ipaddress

from collections import defaultdict
from datetime import timedelta
from functools import reduce

from django.contrib.auth.models import Group
from django.db import DatabaseError, models, transaction
from django.db.models import Q
from django.utils import timezone
from netfields import CidrAddressField, NetManager

from mreg.validators import (validate_hostname, validate_reverse_zone_name,
                             validate_mac_address, validate_loc,
                             validate_naptr_flag, validate_srv_service_text,
                             validate_zones_serialno, validate_16bit_uint,
                             validate_network, validate_ttl, validate_hexadecimal,
                             validate_regex)
from mreg.utils import (create_serialno, encode_mail, clear_none, qualify,
        idna_encode, get_network_from_zonename)

from .fields import LCICharField, DnsNameField
from .models_auth import User

class NameServer(models.Model):
    name = DnsNameField(unique=True)
    ttl = models.IntegerField(blank=True, null=True, validators=[validate_ttl])

    class Meta:
        db_table = 'ns'
        ordering = ('name',)

    def __str__(self):
        return str(self.name)

    def zf_string(self, zone, subzone=None):
        """String representation for zonefile export."""
        if subzone:
            subzone = idna_encode(qualify(subzone, zone))
        data = {
            'subzone': clear_none(subzone),
            'ttl': clear_none(self.ttl),
            'record_type': 'NS',
            'record_data': idna_encode(qualify(self.name, zone))
        }
        return '{subzone:24} {ttl:5} IN {record_type:6} {record_data}\n'.format_map(data)

    @staticmethod
    def validate_name(name):
        validate_hostname(name)


class ZoneHelpers:
    def update_nameservers(self, new_ns):
        existing = set([i.name for i in self.nameservers.all()])
        remove_ns = existing - set(new_ns)
        add_ns = set(new_ns) - existing

        # Remove ns from zone and also delete the NameServer if only
        # used by this zone.
        for ns in remove_ns:
            ns = NameServer.objects.get(name=ns)
            usedcount = 0
            #Must check all zone sets
            for i in ('forwardzone', 'reversezone', 'forwardzonedelegation',
                      'reversezonedelegation'):
                usedcount += getattr(ns, f"{i}_set").count()

            if usedcount == 1:
                ns.delete()
            self.nameservers.remove(ns)

        for ns in add_ns:
            try:
                ns = NameServer.objects.get(name=ns)
            except NameServer.DoesNotExist:
                ns = NameServer(name=ns)
                ns.save()
            self.nameservers.add(ns)
        self.save()

    def remove_nameservers(self):
        self.update_nameservers([])


class BaseZone(models.Model, ZoneHelpers):
    updated_at = models.DateTimeField(auto_now=True)
    updated = models.BooleanField(default=True)
    primary_ns = DnsNameField()
    nameservers = models.ManyToManyField(NameServer, db_column='ns')
    email = models.EmailField()
    serialno = models.BigIntegerField(default=create_serialno, validators=[validate_zones_serialno])
    serialno_updated_at = models.DateTimeField(default=timezone.now)
    # TODO: Configurable? Ask hostmaster
    refresh = models.IntegerField(default=10800)
    retry = models.IntegerField(default=3600)
    expire = models.IntegerField(default=1814400)
    ttl = models.IntegerField(default=43200, validators=[validate_ttl])

    class Meta:
        abstract = True

    def __str__(self):
        return str(self.name)

    @property
    def zf_string(self):
        """String representation for zonefile export."""
        data = {
            'origin': idna_encode(qualify(self.name, self.name, shortform=False)),
            'ttl': self.ttl,
            'name': '@',
            'record_type': 'SOA',
            'mname': idna_encode(qualify(self.primary_ns, self.name, shortform=False)),
            'rname': idna_encode(encode_mail(self.email)),
            'serial': self.serialno,
            'refresh': self.refresh,
            'retry': self.retry,
            'expire': self.expire,
            'zupdated_at': self.updated_at,
            'supdated_at': self.serialno_updated_at
        }
        zf = """$ORIGIN {origin}
$TTL {ttl}
{name:30} IN {record_type:6} {mname} {rname} (
                                         {serial}    ; Serialnumber
                                         {refresh}   ; Refresh
                                         {retry}     ; Retry
                                         {expire}    ; Expire
                                         {ttl} )     ; Negative Cache
; zone.updated_at: {zupdated_at}
; zone.serialno_updated_at: {supdated_at}
""".format_map(data)
        return zf

    def update_serialno(self, force=False):
        """Update serialno if zone has been updated since the serial number
        was updated.
        """
        # Need the have a timedelta as serialno_updated_at to not exhaust
        # the 100 possible daily serial numbers.
        min_delta = timedelta(minutes=1)
        if force or self.updated and \
          timezone.now() > self.serialno_updated_at + min_delta:
            self.serialno = create_serialno(self.serialno)
            self.serialno_updated_at = timezone.now()
            self.updated = False
            try:
                with transaction.atomic():
                    self.save()
            except DatabaseError:
                pass


class ForwardZone(BaseZone):
    name = DnsNameField(unique=True)

    class Meta:
        db_table = 'forward_zone'

    @staticmethod
    def get_zone_by_hostname(name):
        """Get zone by hostname.
        Return zone or None if not found."""

        def _get_reverse_order(lst):
            """Return index of sorted zones"""
            # We must sort the zones to assert that foo.example.org hosts
            # does not end up in the example.org zone.  This is achieved by
            # spelling the zone postfix backwards and sorting the resulting
            # list backwards
            lst = [str(x.name)[::-1] for x in lst]
            t = range(len(lst))
            return sorted(t, key=lambda i: lst[i], reverse=True)

        zones = ForwardZone.objects.all()
        for n in _get_reverse_order(zones):
            z = zones[n]
            if z.name == name:
                return z
            elif name.endswith(f".{z.name}"):
                return z
        return None


class ReverseZone(BaseZone):
    name = DnsNameField(unique=True, validators=[validate_reverse_zone_name])
    # network can not be blank, but it will allow full_clean() to pass, even if
    # the network is not set. Will anyway be overridden by update() and save().
    network = CidrAddressField(unique=True, blank=True)

    objects = NetManager()

    class Meta:
        db_table = 'reverse_zone'

    def update(self, *args, **kwargs):
        self.network = get_network_from_zonename(self.name)
        super().update(*args, **kwargs)

    def save(self, *args, **kwargs):
        self.network = get_network_from_zonename(self.name)
        super().save(*args, **kwargs)

    @staticmethod
    def get_zone_by_ip(ip):
        """Search and return a zone which contains an IP address."""
        return ReverseZone.objects.filter(network__net_contains=ip).first()

    def get_ipaddresses(self):
        network = self.network
        from_ip = str(network.network_address)
        to_ip = str(network.broadcast_address)
        ips = Ipaddress.objects.filter(ipaddress__range=(from_ip, to_ip))
        ips = ips.select_related('host')
        override_ips = dict()
        ptrs = PtrOverride.objects.filter(ipaddress__range=(from_ip, to_ip))
        ptrs = ptrs.select_related('host')
        for p in ptrs:
            override_ips[p.ipaddress] = p
        # XXX: send signal/mail to hostmaster(?) about issues with multiple_ip_no_ptr
        count = defaultdict(int)
        for i in ips:
            if i.ipaddress not in override_ips:
                count[i.ipaddress] += 1
        multiple_ip_no_ptr = {i: count[i] for i in count if count[i] > 1}
        ptr_done = set()
        # Use PtrOverrides when found, but only once. Also skip IPaddresses
        # which have been used multiple times, but lacks a PtrOverride.
        result = []

        def _add_to_result(item):
            ttl = item.host.ttl or ""
            result.append((ipaddress.ip_address(item.ipaddress), ttl, item.host.name))

        for i in ips:
            ip = i.ipaddress
            if ip in multiple_ip_no_ptr:
                continue
            if ip in override_ips:
                if ip not in ptr_done:
                    ptr_done.add(ip)
                    _add_to_result(override_ips[ip])
            else:
                _add_to_result(i)
        # Add PtrOverrides which actually don't override anything,
        # but are only used as PTRs without any Ipaddress object creating
        # forward entries.
        for k, v in override_ips.items():
            if k not in ptr_done:
                _add_to_result(v)

        # Return sorted by IP
        return sorted(result, key=lambda i: i[0])


class ForwardZoneDelegation(models.Model, ZoneHelpers):
    zone = models.ForeignKey(ForwardZone, on_delete=models.CASCADE, db_column='zone', related_name='delegations')
    name = DnsNameField(unique=True)
    nameservers = models.ManyToManyField(NameServer, db_column='ns')

    class Meta:
        db_table = 'forward_zone_delegation'

    def __str__(self):
        return f"{self.zone.name} {self.name}"


class ReverseZoneDelegation(models.Model, ZoneHelpers):
    zone = models.ForeignKey(ReverseZone, on_delete=models.CASCADE, db_column='zone', related_name='delegations')
    name = DnsNameField(unique=True, validators=[validate_reverse_zone_name])
    nameservers = models.ManyToManyField(NameServer, db_column='ns')

    class Meta:
        db_table = 'reverse_zone_delegation'

    def __str__(self):
        return f"{self.zone.name} {self.name}"


class ForwardZoneMember(models.Model):
    zone = models.ForeignKey(ForwardZone, models.DO_NOTHING, db_column='zone', blank=True, null=True)

    class Meta:
        abstract = True

class HinfoPreset(models.Model):
    cpu = models.TextField()
    os = models.TextField()

    class Meta:
        db_table = 'hinfo_preset'
        unique_together = ('cpu', 'os')

    def __str__(self):
        return f"{self.cpu} {self.os}"

    @property
    def zf_string(self):
        """String representation for zonefile export."""
        data = {
            'record_type': 'HINFO',
            'cpu': self.cpu,
            'os': self.os
        }
        return '                                  {record_type:6} {cpu} {os}\n'.format_map(data)


class Host(ForwardZoneMember):
    name = DnsNameField(unique=True)
    contact = models.EmailField()
    ttl = models.IntegerField(blank=True, null=True, validators=[validate_ttl])
    hinfo = models.ForeignKey(HinfoPreset, models.DO_NOTHING, db_column='hinfo', blank=True, null=True)
    loc = models.TextField(blank=True, validators=[validate_loc])
    comment = models.TextField(blank=True)

    class Meta:
        db_table = 'host'


    def __str__(self):
        return str(self.name)

    def loc_string(self, zone):
        """String representation for zonefile export."""
        data = {
            'name': idna_encode(qualify(self.name, zone)),
            'record_type': 'LOC',
            'record_data': self.loc
        }
        return '{name:30} IN {record_type:6} {record_data}\n'.format_map(data)


class Sshfp(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host')
    ttl = models.IntegerField(blank=True, null=True, validators=[validate_ttl])
    algorithm = models.IntegerField(choices=((1, 'RSA'), (2, 'DSS'), (3, 'ECDSA'), (4, 'Ed25519')))
    hash_type = models.IntegerField(choices=((1, 'SHA-1'), (2, 'SHA-256')))
    fingerprint = models.CharField(max_length=64, validators=[validate_hexadecimal])

    class Meta:
        db_table = 'sshfp'

    def __str__(self):
        return (
            f"{self.host.name} -> {self.algorithm} ({self.get_algorithm_display()}) "
            f"{self.hash_type} ({self.get_hash_type_display()}) {self.fingerprint}"
        )


class Ipaddress(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host', related_name='ipaddresses')
    ipaddress = models.GenericIPAddressField()
    macaddress = models.CharField(max_length=17, blank=True, validators=[validate_mac_address])

    class Meta:
        db_table = 'ipaddress'
        unique_together = (('host', 'ipaddress'), )

    def __str__(self):
        return "{} -> {}".format(str(self.ipaddress), str(self.macaddress) or "None")


class Mx(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host', related_name='mxs')
    priority = models.PositiveIntegerField(validators=[validate_16bit_uint])
    mx = DnsNameField()

    class Meta:
        db_table = 'mx'
        unique_together = ('host', 'priority', 'mx')

    def __str__(self):
        return f"{self.priority} {self.mx}"


class PtrOverride(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host', related_name='ptr_overrides')
    ipaddress = models.GenericIPAddressField(unique=True)

    class Meta:
        db_table = 'ptr_override'

    def __str__(self):
        return "{} -> {}".format(str(self.ipaddress), str(self.host.name))


class Txt(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host', related_name='txts')
    txt = models.TextField(max_length=255)

    class Meta:
        db_table = 'txt'
        unique_together = ('host','txt')

    def __str__(self):
        return str(self.txt)


class Cname(ForwardZoneMember):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host', related_name='cnames')
    name = DnsNameField(unique=True)
    ttl = models.IntegerField(blank=True, null=True, validators=[validate_ttl])

    class Meta:
        db_table = 'cname'
        ordering = ('name',)

    def __str__(self):
        return "{} -> {}".format(str(self.name), str(self.host))


class Network(models.Model):
    network = CidrAddressField(unique=True)
    description = models.TextField(blank=True)
    vlan = models.IntegerField(blank=True, null=True)
    dns_delegated = models.BooleanField(default=False)
    category = models.TextField(blank=True)
    location = models.TextField(blank=True)
    frozen = models.BooleanField(default=False)
    reserved = models.PositiveIntegerField(default=3)

    objects = NetManager()

    class Meta:
        db_table = 'network'
        ordering = ('network',)

    def __str__(self):
        return str(self.network)

    def get_reserved_ipaddresses(self):
        """ Returns a set with the reserved ip addresses for the network."""
        network = self.network
        ret = set([network.network_address])
        for i, ip in zip(range(self.reserved), network.hosts()):
            ret.add(ip)
        if isinstance(network, ipaddress.IPv4Network):
            ret.add(network.broadcast_address)
        return ret

    def _get_used_ipaddresses(self):
        from_ip = str(self.network.network_address)
        to_ip = str(self.network.broadcast_address)
        #where_str = "ipaddress BETWEEN '{}' AND '{}'".format(from_ip, to_ip)
        #ips = Ipaddress.objects.extra(where=[where_str])
        return Ipaddress.objects.filter(ipaddress__range=(from_ip, to_ip))

    def get_used_ipaddresses(self):
        """
        Returns the used ipaddress on the network.
        """
        ips = self._get_used_ipaddresses()
        used = {ipaddress.ip_address(i.ipaddress) for i in ips}
        return used

    def get_used_ipaddress_count(self):
        """
        Returns the number of used ipaddreses on the network.
        """
        return self._get_used_ipaddresses().count()

    def get_unused_ipaddresses(self):
        """
        Returns which ip-addresses on the network are unused.
        """
        network_ips = []
        if isinstance(self.network, ipaddress.IPv6Network):
            # Getting all availible IPs for a ipv6 prefix can easily cause
            # the webserver to hang due to lots and lots of IPs. Instead limit
            # to the first 4000 hosts. Should probably be configurable.
            for ip in self.network.hosts():
                if len(network_ips) == 4000:
                    break
                network_ips.append(ip)
        else:
            network_ips = self.network.hosts()

        reserved = self.get_reserved_ipaddresses()
        used = self.get_used_ipaddresses()
        return set(network_ips) - reserved - used

    def get_first_unused(self):
        """
        Return the first unused IP found, if any.
        """

        reserved = self.get_reserved_ipaddresses()
        used = self.get_used_ipaddresses()
        for ip in self.network.hosts():
            if ip in reserved:
                continue
            if ip not in used:
                return str(ip)
        return None


class Naptr(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host', related_name='naptrs')
    preference = models.IntegerField(validators=[validate_16bit_uint])
    order = models.IntegerField(validators=[validate_16bit_uint])
    flag = models.CharField(max_length=1, blank=True, validators=[validate_naptr_flag])
    service = LCICharField(max_length=128, blank=True)
    regex = models.CharField(max_length=128, blank=True)
    replacement = LCICharField(max_length=255)

    class Meta:
        db_table = 'naptr'
        unique_together = ('host', 'preference', 'order', 'flag', 'service',
                           'regex', 'replacement')
        ordering = ('preference', 'order', 'flag', 'service', 'regex', 'replacement')

    def __str__(self):
        return "{} -> {} {} {} {} {} {}".format(self.host, self.preference,
                                                self.order, self.flag,
                                                self.service, self.regex,
                                                self.replacement)


class Srv(ForwardZoneMember):
    name = LCICharField(max_length=255, validators=[validate_srv_service_text])
    priority = models.IntegerField(validators=[validate_16bit_uint])
    weight = models.IntegerField(validators=[validate_16bit_uint])
    port = models.IntegerField(validators=[validate_16bit_uint])
    ttl = models.IntegerField(blank=True, null=True, validators=[validate_ttl])
    # XXX: target MUST not be a alias aka cname
    target = DnsNameField()

    class Meta:
        db_table = 'srv'
        unique_together = ('name', 'priority', 'weight', 'port', 'target')
        ordering = ('name', 'priority', 'weight', 'port', 'target')

    def __str__(self):
        return str(self.name)

    def zf_string(self, zone):
        """String representation for zonefile export."""
        data = {
            'name': idna_encode(qualify(self.name, zone)),
            'ttl': clear_none(self.ttl),
            'record_type': 'SRV',
            'priority': self.priority,
            'weight': self.weight,
            'port': self.port,
            'target': idna_encode(qualify(self.target, zone))
        }
        return '{name:24} {ttl:5} IN {record_type:6} {priority} {weight} {port} {target}\n'.format_map(data)


class HostGroup(models.Model):
    name = LCICharField(max_length=50, unique=True)
    description = models.CharField(max_length=200, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    owners = models.ManyToManyField(Group, blank=True)
    parent = models.ManyToManyField('self', symmetrical=False, blank=True, related_name='groups')
    hosts = models.ManyToManyField(Host, related_name='hostgroups')

    class Meta:
        db_table = 'hostgroup'
        ordering = ('name',)

    def __str__(self):
        return "%s" % self.name


class NetGroupRegexPermission(models.Model):
    group = models.CharField(max_length=80)
    range = CidrAddressField()
    regex = models.CharField(max_length=250, validators=[validate_regex])

    objects = NetManager()

    class Meta:
        db_table = 'perm_net_group_regex'
        unique_together = ('group', 'range', 'regex', )

    def __str__(self):
        return f"group {self.group}, range {self.range}, regex {self.regex}"

    @staticmethod
    def find_perm(groups, hostname, ips):
        if not (groups or hostname or ips):
            return False
        if isinstance(groups, str):
            groups = [groups]
        if not isinstance(groups, (list, tuple)):
            return ValueError(f'groups on invalid type ({type(groups)})')
        if isinstance(ips, str):
            ips = [ips]
        if not isinstance(ips, (list, tuple)):
            return ValueError(f'ips on invalid type ({type(ips)})')
        qs = NetGroupRegexPermission.objects.filter(
                group__in=groups
            ).extra(
                where=["%s ~ regex"], params=[str(hostname)]
            ).filter(
                reduce(lambda x, y: x | y, [Q(range__net_contains=ip) for ip in ips])
            )
        return qs


# TODO: Add user_id functionality when auth is implemented
class ModelChangeLog(models.Model):
    # user_id = models.BigIntegerField(db_index=True)
    table_name = models.CharField(max_length=132)
    table_row = models.BigIntegerField()
    data = models.TextField()
    action = models.CharField(max_length=16)  # saved or deleted
    timestamp = models.DateTimeField()

    class Meta:
        db_table = "model_change_log"
