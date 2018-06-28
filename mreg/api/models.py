# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey has `on_delete` set to the desired behavior.
#   * Remov` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
#
# ===========================================================================
# This model file does not currently correspond to the new database config! |
# ===========================================================================
from django.db import models


class Zones(models.Model):
    zoneid = models.AutoField(primary_key=True)
    name = models.TextField(unique=True)
    primary_ns = models.TextField()
    email = models.TextField(blank=True, null=True)
    serialno = models.IntegerField(blank=True, null=True)
    refresh = models.IntegerField(blank=True, null=True)
    retry = models.IntegerField(blank=True, null=True)
    expire = models.IntegerField(blank=True, null=True)
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'zones'


class Ns(models.Model):
    zoneid = models.ForeignKey(Zones, models.DO_NOTHING, db_column='zoneid')
    name = models.TextField()
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'ns'


class Hosts(models.Model):
    hostid = models.AutoField(primary_key=True)
    name = models.TextField(unique=True)
    ipaddress = models.GenericIPAddressField(unique=True)
    ttl = models.IntegerField(blank=True, null=True)
    macaddress = models.TextField(blank=True, null=True)  # This field type is a guess.
    contact = models.TextField()
    hinfo = models.TextField(blank=True, null=True)
    loc = models.TextField(blank=True, null=True)
    comment = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'hosts'


class Subnets(models.Model):
    range = models.TextField(blank=True, null=True)  # This field type is a guess.
    comment = models.TextField(blank=True, null=True)
    dns_delegated = models.NullBooleanField()

    class Meta:
        db_table = 'subnets'


class ARecords(models.Model):
    hostid = models.ForeignKey(Hosts, models.DO_NOTHING, db_column='hostid', blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    ipaddress = models.GenericIPAddressField(blank=True, null=True)
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'a_records'


class Aaaa(models.Model):
    hostid = models.ForeignKey(Hosts, models.DO_NOTHING, db_column='hostid', blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    ipaddress = models.GenericIPAddressField(blank=True, null=True)
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'aaaa'


class Ptr(models.Model):
    hostid = models.ForeignKey(Hosts, models.DO_NOTHING, db_column='hostid', blank=True, null=True)
    ipaddress = models.GenericIPAddressField(blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    ttl = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'ptr'


class Cname(models.Model):
    name = models.TextField(blank=True, null=True)
    cname = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'cname'


class Naptr(models.Model):
    naptrid = models.AutoField(primary_key=True)
    preference = models.IntegerField(blank=True, null=True)
    orderv = models.IntegerField(blank=True, null=True)
    flag = models.CharField(max_length=1, blank=True, null=True)
    service = models.TextField(blank=True, null=True)
    regex = models.TextField(blank=True, null=True)
    replacement = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'naptr'


class Srv(models.Model):
    srvid = models.AutoField(primary_key=True)
    service = models.TextField(blank=True, null=True)
    proto = models.TextField(blank=True, null=True)
    domain = models.TextField(blank=True, null=True)
    priority = models.IntegerField(blank=True, null=True)
    weight = models.IntegerField(blank=True, null=True)
    port = models.IntegerField(blank=True, null=True)
    ttl = models.IntegerField(blank=True, null=True)
    target = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'srv'


class Txt(models.Model):
    txtid = models.AutoField(primary_key=True)
    hostid = models.ForeignKey(Hosts, models.DO_NOTHING, db_column='hostid')
    txt = models.TextField()

    class Meta:
        db_table = 'txt'
