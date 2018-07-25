from django.db import models
from mreg.validators import *
from mreg.utils import *


class NameServer(models.Model):
    nsid = models.AutoField(primary_key=True, serialize=True)
    name = models.TextField(unique=True)
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'ns'

    def zf_string(self):
        data = {
            'ttl': clean(self.ttl),
            'record_type': 'NS',
            'record_data': qualify(self.name, 'uio.no')
        }
        return '                         {ttl:5} IN {record_type:6} {record_data}\n'.format_map(data)


class Zone(models.Model):
    zoneid = models.AutoField(primary_key=True, serialize=True)
    name = models.TextField(unique=True)
    primary_ns = models.TextField()
    nameservers = models.ManyToManyField(NameServer, db_column='ns')
    email = models.EmailField(blank=True, null=True)
    serialno = models.BigIntegerField(blank=True, null=True, validators=[validate_zones_serialno])
    refresh = models.IntegerField(blank=True, null=True, default=7200)
    retry = models.IntegerField(blank=True, null=True, default=3600)
    expire = models.IntegerField(blank=True, null=True, default=604800)
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'zone'

    def zf_string(self):
        data = {
            'origin': qualify(self.name, 'uio.no'),
            'ttl': self.ttl,
            'name': qualify(self.name, 'uio.no'),
            'record_type': 'SOA',
            'mname': qualify(self.primary_ns, 'uio.no'),
            'rname': qualify(encode_mail(self.email), 'uio.no'),
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


class HinfoPreset(models.Model):
    hinfoid = models.AutoField(primary_key=True, serialize=True)
    cpu = models.TextField()
    os = models.TextField()

    class Meta:
        db_table = 'hinfo_preset'

    def zf_string(self):
        data = {
            'record_type': 'HINFO',
            'cpu': clean(self.cpu),
            'os': clean(self.os)
        }
        return '                                  {record_type:6} {cpu} {os}\n'.format_map(data)


class Host(models.Model):
    hostid = models.AutoField(primary_key=True, serialize=True)
    name = models.TextField(unique=True)
    contact = models.EmailField()
    ttl = models.IntegerField(blank=True, null=True)
    hinfo = models.ForeignKey(HinfoPreset, models.DO_NOTHING, db_column='hinfo', blank=True, null=True)
    loc = models.TextField(blank=True, null=True, validators=[validate_loc])
    comment = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'host'

    def loc_string(self):
        data = {
            'name': self.name,
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

    def zf_string(self):
        if isinstance(ipaddress.ip_address(self.ipaddress), ipaddress.IPv4Address):
            iptype = 'A'
        else:
            iptype = 'AAAA'
        #TODO: Make this generic for other zones than uio.no
        data = {
            'name': qualify(self.hostid.name, 'uio.no'),
            'ttl': clean(self.hostid.ttl),
            'record_type': iptype,
            'record_data': self.ipaddress,
            'comment': comment(clean(self.hostid.comment))
        }
        return '{name:24} {ttl:5} IN {record_type:6} {record_data:39}{comment}\n'.format_map(data)


class PtrOverride(models.Model):
    hostid = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='hostid', related_name='ptr_override')
    ipaddress = models.GenericIPAddressField(unique=True)

    class Meta:
        db_table = 'ptr_override'

    def zf_string(self):
        data = {
            'name': reverse_ip(self.ipaddress) + '.in-addr.arpa.',
            'record_data': qualify(self.hostid.name, 'uio.no'),
            'record_type': 'PTR',
            'comment': comment(clean(self.hostid.comment))
        }
        return '{name:30} IN {record_type:6} {record_data}{comment}\n'.format_map(data)


class Txt(models.Model):
    txtid = models.AutoField(primary_key=True, serialize=True)
    hostid = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='hostid', related_name='txt')
    txt = models.TextField()

    class Meta:
        db_table = 'txt'

    def zf_string(self):
        data = {
            'name': qualify(self.hostid.name, 'uio.no'),
            'ttl': clean(self.hostid.ttl),
            'record_type': 'TXT',
            'record_data': '\"%s\"' % self.txt,
            'comment': comment(clean(self.hostid.comment))
        }
        return '{name:24} {ttl:5}    {record_type:6} {record_data:39}{comment}\n'.format_map(data)


class Cname(models.Model):
    hostid = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='hostid', related_name='cname')
    cname = models.TextField()
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'cname'

    def zf_string(self):
        data = {
            'name': qualify(self.hostid.name, 'uio.no'),
            'ttl': clean(self.ttl),
            'record_type': 'CNAME',
            'record_data': qualify(self.cname, 'uio.no'),
            'comment': comment(clean(self.hostid.comment))
        }
        return '{name:24} {ttl:5} IN {record_type:6} {record_data:39}{comment}\n'.format_map(data)


class Subnet(models.Model):
    subnetid = models.AutoField(primary_key=True, serialize=True)
    range = models.TextField(unique=True)
    description = models.TextField(blank=True, null=True)
    vlan = models.IntegerField(blank=True, null=True)
    dns_delegated = models.NullBooleanField()
    category = models.TextField(blank=True, null=True)
    location = models.TextField(blank=True, null=True)
    frozen = models.NullBooleanField()
    reserved = models.IntegerField(default=3)

    class Meta:
        db_table = 'subnet'


class Naptr(models.Model):
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

    def zf_string(self):
        data = {
            'name': qualify(self.hostid.name, 'uio.no'),
            'ttl': clean(self.hostid.ttl),
            'record_type': 'NAPTR',
            'order': clean(self.orderv),
            'preference': clean(self.preference),
            'flag': clean(self.flag),
            'service': self.service,
            'regex': clean(self.regex),
            'replacement': self.replacement,
            'comment': comment(clean(self.hostid.comment))
        }
        return '{name:24} {ttl:5} IN {record_type:6} {order} {preference} \"{flag}\" \"{service}\" \"{regex}\" {replacement}{comment}\n'.format_map(data)


class Srv(models.Model):
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
        data = {
            'name': qualify(self.service, 'uio.no'),
            'ttl': clean(self.ttl),
            'record_type': 'SRV',
            'priority': clean(self.priority),
            'weight': clean(self.weight),
            'port': clean(self.port),
            'target': qualify(self.target, 'uio.no')
        }
        return '{name:24} {ttl:5} IN {record_type:6} {priority} {weight} {port} {target}\n'.format_map(data)

# TODO: Add user_id functionality when auth is implemented
class ModelChangeLogs(models.Model):
    # user_id = models.BigIntegerField(db_index=True)
    table_name = models.CharField(max_length=132)
    table_row = models.BigIntegerField()
    data = models.TextField()
    action = models.CharField(max_length=16)  # saved or deleted
    timestamp = models.DateTimeField()

    class Meta:
        db_table = "model_change_logs"
