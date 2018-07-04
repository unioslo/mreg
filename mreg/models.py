from django.db import models
from mreg.validators import *


class Zones(models.Model):
    zoneid = models.AutoField(primary_key=True, serialize=True)
    name = models.TextField(unique=True)
    primary_ns = models.TextField()
    email = models.EmailField(blank=True, null=True)
    serialno = models.BigIntegerField(blank=True, null=True)
    refresh = models.IntegerField(blank=True, null=True)
    retry = models.IntegerField(blank=True, null=True)
    expire = models.IntegerField(blank=True, null=True)
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'zones'


# TODO: Find a way to move validations via signals to some local_validations?
models.signals.pre_save.connect(validate_zones_refresh_retry_expire, sender=Zones)
models.signals.pre_save.connect(validate_zones_serialno, sender=Zones)


class Ns(models.Model):
    nsid = models.AutoField(primary_key=True, serialize=True)
    zoneid = models.ForeignKey('Zones', models.DO_NOTHING, db_column='zoneid')
    name = models.TextField()
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'ns'


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
    loc = models.TextField(blank=True, null=True)
    comment = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'hosts'


models.signals.pre_save.connect(validate_loc, sender=Hosts)


class Ipaddress(models.Model):
    hostid = models.ForeignKey(Hosts, models.DO_NOTHING, db_column='hostid')
    ipaddress = models.GenericIPAddressField(unique=True)
    macaddress = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'ipaddress'


models.signals.pre_save.connect(validate_mac_address, sender=Ipaddress)


class PtrOverride(models.Model):
    hostid = models.ForeignKey(Hosts, models.DO_NOTHING, db_column='hostid')
    ipaddress = models.GenericIPAddressField(unique=True)

    class Meta:
        db_table = 'ptr_override'


class Txt(models.Model):
    txtid = models.AutoField(primary_key=True, serialize=True)
    hostid = models.ForeignKey(Hosts, models.DO_NOTHING, db_column='hostid')
    txt = models.TextField()

    class Meta:
        db_table = 'txt'


class Cname(models.Model):
    hostid = models.ForeignKey('Hosts', models.DO_NOTHING, db_column='hostid')
    cname = models.TextField()
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'cname'


class Subnets(models.Model):
    subnetid = models.AutoField(primary_key=True, serialize=True)
    range = models.TextField()  #TODO Need CIDR support
    description = models.TextField(blank=True, null=True)
    vlan = models.IntegerField(blank=True, null=True)
    dns_delegated = models.NullBooleanField()

    class Meta:
        db_table = 'subnets'


class Naptr(models.Model):
    naptrid = models.AutoField(primary_key=True, serialize=True)
    hostid = models.ForeignKey('Hosts', models.DO_NOTHING, db_column='hostid')
    preference = models.IntegerField(blank=True, null=True)
    orderv = models.IntegerField(blank=True, null=True)
    flag = models.CharField(max_length=1, blank=True, null=True)
    service = models.TextField()
    regex = models.TextField(blank=True, null=True)
    replacement = models.TextField()

    class Meta:
        db_table = 'naptr'


models.signals.pre_save.connect(validate_naptr_flag, sender=Naptr)


class Srv(models.Model):
    srvid = models.AutoField(primary_key=True, serialize=True)
    service = models.TextField()
    priority = models.IntegerField(blank=True, null=True)
    weight = models.IntegerField(blank=True, null=True)
    port = models.IntegerField(blank=True, null=True)
    ttl = models.IntegerField(blank=True, null=True)
    target = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'srv'


models.signals.pre_save.connect(validate_srv_service_text, sender=Srv)
