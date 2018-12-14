import ipaddress

from collections import defaultdict
from datetime import timedelta

from django.db import models
from django.utils import timezone

from mreg.validators import (validate_hostname, validate_zonename,
        validate_mac_address, validate_loc, validate_naptr_flag,
        validate_srv_service_text, validate_zones_serialno,
        validate_16bit_uint)
from mreg.utils import (create_serialno, encode_mail, clear_none, qualify,
        idna_encode, get_network_from_zonename)


class NameServer(models.Model):
    name = models.CharField(unique=True, max_length=253, validators=[validate_hostname])
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'ns'

    def __str__(self):
        return str(self.name)

    def zf_string(self, zone):
        """String representation for zonefile export."""
        data = {
            'ttl': clear_none(self.ttl),
            'record_type': 'NS',
            'record_data': idna_encode(qualify(self.name, zone))
        }
        return '                         {ttl:5} IN {record_type:6} {record_data}\n'.format_map(data)


class Zone(models.Model):
    name = models.CharField(unique=True, max_length=253, validators=[validate_zonename])
    updated_at = models.DateTimeField(auto_now=True)
    primary_ns = models.CharField(max_length=253, validators=[validate_hostname])
    nameservers = models.ManyToManyField(NameServer, db_column='ns')
    email = models.EmailField()
    serialno = models.BigIntegerField(default=create_serialno, validators=[validate_zones_serialno])
    serialno_updated_at = models.DateTimeField(default=timezone.now)
    # TODO: Configurable? Ask hostmaster
    refresh = models.IntegerField(default=10800)
    retry = models.IntegerField(default=3600)
    expire = models.IntegerField(default=1814400)
    ttl = models.IntegerField(default=43200)

    class Meta:
        db_table = 'zone'

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
        # Need the have a timedelta as serialno_update_at is set before
        # zone.save() which updates zone.updated_at, but also to not exhaust
        # the 100 possible daily serial numbers.
        if force or \
          self.updated_at > self.serialno_updated_at + timedelta(minutes=1):
            self.serialno = create_serialno(self.serialno)
            self.serialno_updated_at = timezone.now()
            self.save()

    @property
    def network(self):
        return get_network_from_zonename(self.name)

    def get_ipaddresses(self):
        network = self.network
        from_ip = str(network.network_address)
        to_ip = str(network.broadcast_address)
        ips = Ipaddress.objects.filter(ipaddress__range=(from_ip, to_ip)).order_by("ipaddress")
        override_ips = dict()
        for p in PtrOverride.objects.filter(ipaddress__range=(from_ip, to_ip)):
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
        for i in ips:
            ip = i.ipaddress
            if ip in multiple_ip_no_ptr:
                continue
            if ip in override_ips:
                if ip not in ptr_done:
                    ptr_done.add(ip)
                    yield override_ips[ip]
            else:
                yield i


class ZoneMember(models.Model):
    zone = models.ForeignKey(Zone, models.DO_NOTHING, db_column='zone', blank=True, null=True)

    class Meta:
        abstract = True


class HinfoPreset(models.Model):
    cpu = models.TextField()
    os = models.TextField()

    class Meta:
        db_table = 'hinfo_preset'
        unique_together = ('cpu', 'os')

    def __str__(self):
        return "{} {}".format(str(self.cpu), str(self.os))

    @property
    def zf_string(self):
        """String representation for zonefile export."""
        data = {
            'record_type': 'HINFO',
            'cpu': self.cpu,
            'os': self.os
        }
        return '                                  {record_type:6} {cpu} {os}\n'.format_map(data)


class Host(ZoneMember):
    name = models.CharField(unique=True, max_length=253, validators=[validate_hostname])
    contact = models.EmailField()
    ttl = models.IntegerField(blank=True, null=True)
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


class Ipaddress(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host', related_name='ipaddresses')
    ipaddress = models.GenericIPAddressField()
    macaddress = models.CharField(max_length=17, blank=True, validators=[validate_mac_address])

    class Meta:
        db_table = 'ipaddress'
        unique_together = (('host', 'ipaddress'), )

    def __str__(self):
        return "{} -> {}".format(str(self.ipaddress), str(self.macaddress) or "None")

    def zf_string(self, zone):
        """String representation for forward zonefile export."""
        if isinstance(ipaddress.ip_address(self.ipaddress), ipaddress.IPv4Address):
            iptype = 'A'
        else:
            iptype = 'AAAA'
        data = {
            'name': idna_encode(qualify(self.host.name, zone)),
            'ttl': clear_none(self.host.ttl),
            'record_type': iptype,
            'record_data': self.ipaddress,
        }
        return '{name:24} {ttl:5} IN {record_type:6} {record_data:39}\n'.format_map(data)


class PtrOverride(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host', related_name='ptr_overrides')
    ipaddress = models.GenericIPAddressField(unique=True)

    class Meta:
        db_table = 'ptr_override'

    def __str__(self):
        return "{} -> {}".format(str(self.ipaddress), str(self.host.name))

    def zf_string(self, zone):
        """String representation for zonefile export."""
        data = {
            'name': ipaddress.ip_address(self.ipaddress).reverse_pointer,
            'record_data': idna_encode(qualify(self.host.name, zone)),
            'record_type': 'PTR',
        }
        return '{name:30} IN {record_type:6} {record_data}\n'.format_map(data)


class Txt(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host', related_name='txts')
    txt = models.TextField(max_length=255)

    class Meta:
        db_table = 'txt'
        unique_together = ('host','txt')

    def __str__(self):
        return str(self.txt)

    def zf_string(self, zone):
        """String representation for zonefile export."""
        data = {
            'name': idna_encode(qualify(self.host.name, zone)),
            'ttl': clear_none(self.host.ttl),
            'record_type': 'TXT',
            'record_data': '\"%s\"' % self.txt,
        }
        return '{name:24} {ttl:5} IN {record_type:6} {record_data:39}\n'.format_map(data)


class Cname(ZoneMember):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host', related_name='cnames')
    name = models.CharField(max_length=255, unique=True)
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'cname'
        ordering = ('name',)

    def __str__(self):
        return "{} -> {}".format(str(self.name), str(self.host))

    def zf_string(self, zone):
        """String representation for zonefile export."""
        data = {
            'name': idna_encode(qualify(self.name, zone)),
            'ttl': clear_none(self.ttl),
            'record_type': 'CNAME',
            'record_data': idna_encode(qualify(self.host.name, zone)),
        }
        return '{name:24} {ttl:5} IN {record_type:6} {record_data:39}\n'.format_map(data)


class Subnet(models.Model):
    range = models.TextField(unique=True)
    description = models.TextField(blank=True)
    vlan = models.IntegerField(blank=True, null=True)
    dns_delegated = models.NullBooleanField()
    category = models.TextField(blank=True)
    location = models.TextField(blank=True)
    frozen = models.NullBooleanField()
    reserved = models.PositiveIntegerField(default=3)

    class Meta:
        db_table = 'subnet'
        ordering = ('range',)

    def __str__(self):
        return str(self.range)

    @property
    def network(self):
        return ipaddress.ip_network(self.range)

    def get_reserved_ipaddresses(self):
        """ Returns a set with the reserved ip addresses for the subnet."""
        subnet = self.network
        ret = set([subnet.network_address])
        for i, ip in zip(range(self.reserved), subnet.hosts()):
            ret.add(ip)
        if isinstance(subnet, ipaddress.IPv4Network):
            ret.add(subnet.broadcast_address)
        return ret

    def _get_used_ipaddresses(self):
        from_ip = str(self.network.network_address)
        to_ip = str(self.network.broadcast_address)
        #where_str = "ipaddress BETWEEN '{}' AND '{}'".format(from_ip, to_ip)
        #ips = Ipaddress.objects.extra(where=[where_str])
        return Ipaddress.objects.filter(ipaddress__range=(from_ip, to_ip))

    def get_used_ipaddresses(self):
        """
        Returns the used ipaddress on the subnet.
        """
        ips = self._get_used_ipaddresses()
        used = {ipaddress.ip_address(i.ipaddress) for i in ips}
        return used

    def get_used_ipaddress_count(self):
        """
        Returns the number of used ipaddreses on the subnet.
        """
        return self._get_used_ipaddresses().count()

    def get_unused_ipaddresses(self):
        """
        Returns which ip-addresses on the subnet are unused.
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

    @staticmethod
    def overlap_check(subnet):
        """
        Check if a subnet overlaps existing subnet(s).
        Return a list of overlapped subnets.
        """
        where = [ "range::inet && inet %s" ]
        return Subnet.objects.extra(where=where, params=[str(subnet)])

    @staticmethod
    def get_subnet_by_ip(ip):
        """Search and return a subnet which contains an IP address."""
        where = [ "inet %s <<= range::inet" ]
        return Subnet.objects.extra(where=where, params=[str(ip)]).first()

class Naptr(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host', related_name='naptrs')
    preference = models.IntegerField(validators=[validate_16bit_uint])
    order = models.IntegerField(validators=[validate_16bit_uint])
    flag = models.CharField(max_length=1, blank=True, validators=[validate_naptr_flag])
    service = models.CharField(max_length=255, blank=True)
    regex = models.TextField(blank=True)
    replacement = models.CharField(max_length=255)

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

    def zf_string(self, zone):
        """String representation for zonefile export."""
        if self.flag in ('a', 's'):
            replacement = idna_encode(qualify(self.replacement, zone))
        else:
            replacement = self.replacement

        data = {
            'name': idna_encode(qualify(self.host.name, zone)),
            'ttl': clear_none(self.host.ttl),
            'record_type': 'NAPTR',
            'order': self.order,
            'preference': self.preference,
            'flag': self.flag,
            'service': self.service,
            'regex': self.regex,
            'replacement': replacement,
        }
        return '{name:24} {ttl:5} IN {record_type:6} {order} {preference} \"{flag}\" \"{service}\" \"{regex}\" {replacement}\n'.format_map(data)


class Srv(ZoneMember):
    name = models.TextField(validators=[validate_srv_service_text])
    priority = models.IntegerField(validators=[validate_16bit_uint])
    weight = models.IntegerField(validators=[validate_16bit_uint])
    port = models.IntegerField(validators=[validate_16bit_uint])
    ttl = models.IntegerField(blank=True, null=True)
    # XXX: target MUST not be a alias aka cname
    target = models.CharField(max_length=255)

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
    hostgroup_name = models.CharField(max_length=50, unique=True)
    parent = models.ManyToManyField('self', symmetrical=False, blank=True, related_name='groups')

    def __str__(self):
        return("%s" % (self.id))


class HostGroupMember(models.Model):
    hostid = models.ForeignKey(Host, on_delete=models.PROTECT, db_column='hostid', related_name='hostgroupmember')
    group = models.ForeignKey(HostGroup, on_delete=models.PROTECT)

    def __str__(self):
        return('%s' % (self.id))


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
