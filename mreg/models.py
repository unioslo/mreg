from django.db import models
from mreg.validators import *
import ipaddress


def clean(value):
    """
    Cleans up potential Nones into empty strings instead
    :param value: Value to check
    :return: Unmodified value or empty string
    """
    if value is None:
        value = ""
    return value


def comment(string):
    """
    Turns not-empty string into comments
    :param string: String to check
    :return: Commented or empty string
    """
    if string != "":
        string = ' ; %s' % string
    return string


def reverse_ip(ip):
    """
    Reverses an IP-adddress
    :param ip: IP-address to reverse
    :return: IP-address in reverse
    """
    if isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address):
        return ':'.join(reversed(ip.split(':')))
    else:
        return '.'.join(reversed(ip.split('.')))


def qualify(name, zone):
    """
    Appends a punctuation mark to fully qualified names within a given zone
    :param name: Name to check
    :param zone: Zone where name might be
    :return: String with punctuation appended or unchanged
    """
    if name.endswith(zone):
        name += '.'
    return name


def encode_mail(mail):
    """
    Encodes an e-mail address as a name by converting '.' to '\.' and '@' to '.'
    :param mail: E-mail address to encode
    :return: Encoded e-mail address
    """
    user, domain = mail.split('@')
    user = user.replace('.', '\.')
    mail = '%s.%s' % (user, domain)
    return mail


class Ns(models.Model):
    # TODO: zoneid-field is likey not necessary at all, since addition of
    # TODO: nameservers field to Zones model.
    nsid = models.AutoField(primary_key=True, serialize=True)
    name = models.TextField(unique=True)
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'ns'

    def zf_string(self):
        data = {
            'ttl': clean(self.ttl),
            'record_data': self.name
        }
        return '    {ttl} IN NS {record_data}'.format_map(data)


class Zones(models.Model):
    zoneid = models.AutoField(primary_key=True, serialize=True)
    name = models.TextField(unique=True)
    primary_ns = models.TextField()
    nameservers = models.ManyToManyField(Ns, db_column='ns')
    email = models.EmailField(blank=True, null=True)
    serialno = models.BigIntegerField(blank=True, null=True, validators=[validate_zones_serialno])
    refresh = models.IntegerField(blank=True, null=True)
    retry = models.IntegerField(blank=True, null=True)
    expire = models.IntegerField(blank=True, null=True)
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'zones'

    def zf_string(self):
        data = {
            'origin': qualify(self.name, 'uio.no'),
            'ttl': self.ttl,
            'name': qualify(self.name, 'uio.no'),
            'mname': qualify(self.primary_ns, 'uio.no'),
            'rname': qualify(encode_mail(self.email), 'uio.no'),
            'serial': self.serialno,
            'refresh': self.refresh,
            'retry': self.retry,
            'expire': self.expire,
        }
        zf = """$ORIGIN {origin}
$TTL {ttl}
{name} IN SOA {mname} {rname} (
    {serial}    ; Serialnumber
    {refresh}   ; Refresh
    {retry}     ; Retry
    {expire}    ; Expire
    {ttl} )     ; Negative Cache""".format_map(data)
        return zf


class HinfoPresets(models.Model):
    hinfoid = models.AutoField(primary_key=True, serialize=True)
    cpu = models.TextField()
    os = models.TextField()

    class Meta:
        db_table = 'hinfo_presets'

    def zf_string(self):
        data = {
            'cpu': clean(self.cpu),
            'os': clean(self.os)
        }
        return '    HINFO {cpu} {os}'.format_map(data)


class Hosts(models.Model):
    hostid = models.AutoField(primary_key=True, serialize=True)
    name = models.TextField(unique=True)
    contact = models.EmailField()
    ttl = models.IntegerField(blank=True, null=True)
    hinfo = models.ForeignKey(HinfoPresets, models.DO_NOTHING, db_column='hinfo', blank=True, null=True)
    loc = models.TextField(blank=True, null=True, validators=[validate_loc])
    comment = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'hosts'


class Ipaddress(models.Model):
    # TODO: Add ForeignKey field for subnet
    hostid = models.ForeignKey(Hosts, on_delete=models.CASCADE, db_column='hostid', related_name='ipaddress')
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
        return '{name} {ttl} IN {record_type} {record_data}{comment}'.format_map(data)


class PtrOverride(models.Model):
    hostid = models.ForeignKey(Hosts, on_delete=models.CASCADE, db_column='hostid', related_name='ptr_override')
    ipaddress = models.GenericIPAddressField(unique=True)

    class Meta:
        db_table = 'ptr_override'

    def zf_string(self):
        data = {
            'name': reverse_ip(self.ipaddress) + '.in-addr.arpa.',
            'record_data': qualify(self.hostid.name, 'uio.no'),
            'comment': comment(clean(self.hostid.comment))
        }
        return '{name} IN PTR {record_data}{comment}'.format_map(data)


class Txt(models.Model):
    txtid = models.AutoField(primary_key=True, serialize=True)
    hostid = models.ForeignKey(Hosts, on_delete=models.CASCADE, db_column='hostid', related_name='txt')
    txt = models.TextField()

    class Meta:
        db_table = 'txt'

    def zf_string(self):
        data = {
            'name': qualify(self.hostid.name, 'uio.no'),
            'ttl': clean(self.hostid.ttl),
            'record_data': '\"%s\"' % self.txt,
            'comment': comment(clean(self.hostid.comment))
        }
        return '{name} {ttl} TXT {record_data}{comment}'.format_map(data)


class Cname(models.Model):
    hostid = models.ForeignKey(Hosts, on_delete=models.CASCADE, db_column='hostid', related_name='cname')
    cname = models.TextField()
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'cname'

    def zf_string(self):
        data = {
            'name': qualify(self.hostid.name, 'uio.no'),
            'ttl': clean(self.ttl),
            'record_data': qualify(self.cname, 'uio.no'),
            'comment': comment(clean(self.hostid.comment))
        }
        return '{name} {ttl} IN CNAME {record_data}{comment}'.format_map(data)


class Subnets(models.Model):
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
        db_table = 'subnets'


class Naptr(models.Model):
    naptrid = models.AutoField(primary_key=True, serialize=True)
    hostid = models.ForeignKey(Hosts, on_delete=models.CASCADE, db_column='hostid', related_name='naptr')
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
            'order': clean(self.orderv),
            'preference': clean(self.preference),
            'flag': clean(self.flag),
            'service': self.service,
            'regex': clean(self.regex),
            'replacement': self.replacement,
            'comment': comment(clean(self.hostid.comment))
        }
        return '{name} {ttl} IN NAPTR {order} {preference} \"{flag}\" \"{service}\" \"{regex}\" {replacement}{comment}'.format_map(data)


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
            'priority': clean(self.priority),
            'weight': clean(self.weight),
            'port': clean(self.port),
            'target': qualify(self.target, 'uio.no')
        }
        return '{name} {ttl} IN SRV {priority} {weight} {port} {target}'.format_map(data)
