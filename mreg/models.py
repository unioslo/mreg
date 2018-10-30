import ipaddress

from django.db import models
from mreg.validators import *
from mreg.utils import *


class NameServer(models.Model):
    nsid = models.AutoField(primary_key=True, serialize=True)
    name = models.CharField(unique=True, max_length=253, validators=[validate_hostname])
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'ns'

    def zf_string(self, zone):
        """String representation for zonefile export."""
        data = {
            'ttl': clear_none(self.ttl),
            'record_type': 'NS',
            'record_data': idna_encode(qualify(self.name, zone))
        }
        return '                         {ttl:5} IN {record_type:6} {record_data}\n'.format_map(data)


class Zone(models.Model):
    zoneid = models.AutoField(primary_key=True, serialize=True)
    name = models.CharField(unique=True, max_length=253, validators=[validate_zonename])
    primary_ns = models.CharField(unique=True, max_length=253, validators=[validate_hostname])
    nameservers = models.ManyToManyField(NameServer, db_column='ns')
    email = models.EmailField()
    serialno = models.BigIntegerField(blank=True, null=True, validators=[validate_zones_serialno])
    # TODO: Configurable? Ask hostmaster
    refresh = models.IntegerField(default=10800)
    retry = models.IntegerField(default=3600)
    expire = models.IntegerField(default=1814400)
    ttl = models.IntegerField(default=43200)

    class Meta:
        db_table = 'zone'

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
        }
        zf = """$ORIGIN {origin}
$TTL {ttl}
{name:30} IN {record_type:6} {mname} {rname} (
                                         {serial}    ; Serialnumber
                                         {refresh}   ; Refresh
                                         {retry}     ; Retry
                                         {expire}    ; Expire
                                         {ttl} )     ; Negative Cache\n""".format_map(data)
        return zf


class ZoneMember(models.Model):
    zoneid = models.ForeignKey(Zone, models.DO_NOTHING, db_column='zone', blank=True, null=True)

    class Meta:
        abstract = True


class HinfoPreset(models.Model):
    hinfoid = models.AutoField(primary_key=True, serialize=True)
    cpu = models.TextField()
    os = models.TextField()

    class Meta:
        db_table = 'hinfo_preset'
        unique_together = ('cpu', 'os')

    @property
    def zf_string(self):
        """String representation for zonefile export."""
        data = {
            'record_type': 'HINFO',
            'cpu': clear_none(self.cpu),
            'os': clear_none(self.os)
        }
        return '                                  {record_type:6} {cpu} {os}\n'.format_map(data)


class Host(ZoneMember):
    hostid = models.AutoField(primary_key=True, serialize=True)
    name = models.CharField(unique=True, max_length=253, validators=[validate_hostname])
    contact = models.EmailField()
    ttl = models.IntegerField(blank=True, null=True)
    hinfo = models.ForeignKey(HinfoPreset, models.DO_NOTHING, db_column='hinfo', blank=True, null=True)
    loc = models.TextField(blank=True, null=True, validators=[validate_loc])
    comment = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'host'

    def loc_string(self, zone):
        """String representation for zonefile export."""
        data = {
            'name': idna_encode(qualify(self.name, zone)),
            'record_type': 'LOC',
            'record_data': self.loc
        }
        return '{name:30} IN {record_type:6} {record_data}\n'.format_map(data)


class Ipaddress(models.Model):
    hostid = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='hostid', related_name='ipaddress')
    ipaddress = models.GenericIPAddressField(unique=True)
    macaddress = models.TextField(blank=True, null=True, validators=[validate_mac_address])

    class Meta:
        db_table = 'ipaddress'

    def zf_string(self, zone):
        """String representation for forward zonefile export."""
        if isinstance(ipaddress.ip_address(self.ipaddress), ipaddress.IPv4Address):
            iptype = 'A'
        else:
            iptype = 'AAAA'
        data = {
            'name': idna_encode(qualify(self.hostid.name, zone)),
            'ttl': clear_none(self.hostid.ttl),
            'record_type': iptype,
            'record_data': self.ipaddress,
        }
        return '{name:24} {ttl:5} IN {record_type:6} {record_data:39}\n'.format_map(data)


class PtrOverride(models.Model):
    hostid = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='hostid', related_name='ptr_override')
    ipaddress = models.GenericIPAddressField(unique=True)

    class Meta:
        db_table = 'ptr_override'

    def zf_string(self, zone):
        """String representation for zonefile export."""
        data = {
            'name': reverse_ip(self.ipaddress) + '.in-addr.arpa.',
            'record_data': idna_encode(qualify(self.hostid.name, zone)),
            'record_type': 'PTR',
        }
        return '{name:30} IN {record_type:6} {record_data}\n'.format_map(data)


class Txt(ZoneMember):
    txtid = models.AutoField(primary_key=True, serialize=True)
    hostid = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='hostid', related_name='txt')
    txt = models.TextField(max_length=255)

    class Meta:
        db_table = 'txt'

    def zf_string(self, zone):
        """String representation for zonefile export."""
        data = {
            'name': idna_encode(qualify(self.hostid.name, zone)),
            'ttl': clear_none(self.hostid.ttl),
            'record_type': 'TXT',
            'record_data': '\"%s\"' % self.txt,
        }
        return '{name:24} {ttl:5} IN {record_type:6} {record_data:39}\n'.format_map(data)


class Cname(ZoneMember):
    hostid = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='hostid', related_name='cname')
    cname = models.TextField()
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'cname'

    def zf_string(self, zone):
        """String representation for zonefile export."""
        data = {
            'name': idna_encode(qualify(self.hostid.name, zone)),
            'ttl': clear_none(self.ttl),
            'record_type': 'CNAME',
            'record_data': idna_encode(qualify(self.cname, zone)),
        }
        return '{name:24} {ttl:5} IN {record_type:6} {record_data:39}\n'.format_map(data)


class Subnet(models.Model):
    subnetid = models.AutoField(primary_key=True, serialize=True)
    range = models.TextField(unique=True)
    description = models.TextField(blank=True, null=True)
    vlan = models.IntegerField(blank=True, null=True)
    dns_delegated = models.NullBooleanField()
    category = models.TextField(blank=True, null=True)
    location = models.TextField(blank=True, null=True)
    frozen = models.NullBooleanField()
    reserved = models.PositiveIntegerField(default=3)

    class Meta:
        db_table = 'subnet'

    def __str__(self):
        return self.range

    def get_reserved_addresses(self):
        """ Returns a set with the reserved ip addresses for the subnet."""
        subnet = ipaddress.ip_network(self.range)
        ret = set([subnet.network_address])
        for i, ip in zip(range(self.reserved), subnet.hosts()):
            ret.add(ip)
        if isinstance(subnet, ipaddress.IPv4Network):
            ret.add(subnet.broadcast_address)
        return ret

class Naptr(ZoneMember):
    naptrid = models.AutoField(primary_key=True, serialize=True)
    hostid = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='hostid', related_name='naptr')
    preference = models.IntegerField(blank=True, null=True)
    orderv = models.IntegerField(blank=True, null=True)
    flag = models.CharField(max_length=1, blank=True, null=True, validators=[validate_naptr_flag])
    service = models.TextField()
    regex = models.TextField(blank=True, null=True)
    replacement = models.TextField()

    class Meta:
        db_table = 'naptr'

    def zf_string(self, zone):
        """String representation for zonefile export."""
        data = {
            'name': idna_encode(qualify(self.hostid.name, zone)),
            'ttl': clear_none(self.hostid.ttl),
            'record_type': 'NAPTR',
            'order': clear_none(self.orderv),
            'preference': clear_none(self.preference),
            'flag': clear_none(self.flag),
            'service': self.service,
            'regex': clear_none(self.regex),
            'replacement': self.replacement,
        }
        return '{name:24} {ttl:5} IN {record_type:6} {order} {preference} \"{flag}\" \"{service}\" \"{regex}\" {replacement}\n'.format_map(data)


class Srv(ZoneMember):
    srvid = models.AutoField(primary_key=True, serialize=True)
    service = models.TextField(validators=[validate_srv_service_text])
    priority = models.IntegerField(blank=True, null=True)
    weight = models.IntegerField(blank=True, null=True)
    port = models.IntegerField(blank=True, null=True)
    ttl = models.IntegerField(blank=True, null=True)
    target = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'srv'

    def zf_string(self):
        """String representation for zonefile export."""
        data = {
            'name': idna_encode(qualify(self.service, zone)),
            'ttl': clear_none(self.ttl),
            'record_type': 'SRV',
            'priority': clear_none(self.priority),
            'weight': clear_none(self.weight),
            'port': clear_none(self.port),
            'target': idna_encode(qualify(self.target, zone))
        }
        return '{name:24} {ttl:5} IN {record_type:6} {priority} {weight} {port} {target}\n'.format_map(data)


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
