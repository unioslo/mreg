from django.db import models
from mreg.validators import *
from django.core.exceptions import ValidationError


class Ns(models.Model):
    # TODO: zoneid-field is likey not necessary at all, since addition of
    # TODO: nameservers field to Zones model.
    nsid = models.AutoField(primary_key=True, serialize=True)
    name = models.TextField(unique=True)
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'ns'


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


class HinfoPresets(models.Model):
    hinfoid = models.AutoField(primary_key=True, serialize=True)
    cpu = models.TextField()
    os = models.TextField()

    class Meta:
        db_table = 'hinfo_presets'


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
    hostid = models.ForeignKey(Hosts, models.DO_NOTHING, db_column='hostid', related_name='ipaddress')
    ipaddress = models.GenericIPAddressField(unique=True)
    macaddress = models.TextField(blank=True, null=True, validators=[validate_mac_address])

    class Meta:
        db_table = 'ipaddress'


class PtrOverride(models.Model):
    hostid = models.ForeignKey(Hosts, models.DO_NOTHING, db_column='hostid', related_name='ptr_override')
    ipaddress = models.GenericIPAddressField(unique=True)

    class Meta:
        db_table = 'ptr_override'


class Txt(models.Model):
    txtid = models.AutoField(primary_key=True, serialize=True)
    hostid = models.ForeignKey(Hosts, models.DO_NOTHING, db_column='hostid', related_name='txt')
    txt = models.TextField()

    class Meta:
        db_table = 'txt'


class Cname(models.Model):
    hostid = models.ForeignKey(Hosts, models.DO_NOTHING, db_column='hostid', related_name='cname')
    cname = models.TextField()
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'cname'


class Subnets(models.Model):
    subnetid = models.AutoField(primary_key=True, serialize=True)
    range = models.TextField()
    description = models.TextField(blank=True, null=True)
    vlan = models.IntegerField(blank=True, null=True)
    dns_delegated = models.NullBooleanField()
    category = models.TextField(blank=True, null=True)
    location = models.TextField(blank=True, null=True)
    frozen = models.NullBooleanField()

    class Meta:
        db_table = 'subnets'


class Naptr(models.Model):
    naptrid = models.AutoField(primary_key=True, serialize=True)
    hostid = models.ForeignKey(Hosts, models.DO_NOTHING, db_column='hostid', related_name='naptr')
    preference = models.IntegerField(blank=True, null=True)
    orderv = models.IntegerField(blank=True, null=True)
    flag = models.CharField(max_length=1, blank=True, null=True, validators=[validate_naptr_flag])
    service = models.TextField()
    regex = models.TextField(blank=True, null=True)
    replacement = models.TextField()

    class Meta:
        db_table = 'naptr'


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
