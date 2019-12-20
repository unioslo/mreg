import ipaddress
import random
from collections import defaultdict
from datetime import timedelta
from functools import reduce

import django.contrib.postgres.fields as pgfields
from django.contrib.auth.models import Group
from django.db import DatabaseError, models, transaction
from django.db.models import Q
from django.utils import timezone
from netfields import CidrAddressField, NetManager

from .fields import DnsNameField, LCICharField
from .models_auth import User  # noqa: F401, needed by mreg.settings for now
from .utils import (
    clear_none,
    create_serialno,
    encode_mail,
    get_network_from_zonename,
    idna_encode,
    qualify,
)
from .validators import (
    validate_16bit_uint,
    validate_32bit_uint,
    validate_hexadecimal,
    validate_hostname,
    validate_loc,
    validate_mac_address,
    validate_naptr_flag,
    validate_regex,
    validate_reverse_zone_name,
    validate_srv_service_text,
    validate_ttl,
)


class BaseModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class NameServer(BaseModel):
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
        existing = {i.name for i in self.nameservers.all()}
        remove_ns = existing - set(new_ns)
        add_ns = set(new_ns) - existing

        # Remove ns from zone and also delete the NameServer if only
        # used by this zone.
        for ns in remove_ns:
            ns = NameServer.objects.get(name=ns)
            usedcount = 0
            # Must check all zone sets
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


class BaseZone(BaseModel, ZoneHelpers):
    updated = models.BooleanField(default=True)
    primary_ns = DnsNameField()
    nameservers = models.ManyToManyField(NameServer, db_column='ns')
    email = pgfields.CIEmailField()
    serialno = models.BigIntegerField(default=create_serialno,
                                      validators=[validate_32bit_uint])
    serialno_updated_at = models.DateTimeField(default=timezone.now)
    refresh = models.IntegerField(default=10800)
    retry = models.IntegerField(default=3600)
    expire = models.IntegerField(default=1814400)
    soa_ttl = models.IntegerField(default=43200, validators=[validate_ttl])
    default_ttl = models.IntegerField(default=43200, validators=[validate_ttl])

    class Meta:
        abstract = True

    def __str__(self):
        return str(self.name)

    @property
    def zf_string(self):
        """String representation for zonefile export."""
        data = {
            'origin': idna_encode(qualify(self.name, self.name, shortform=False)),
            'default_ttl': self.default_ttl,
            'name': '@',
            'record_type': 'SOA',
            'mname': idna_encode(qualify(self.primary_ns, self.name, shortform=False)),
            'rname': idna_encode(encode_mail(self.email)),
            'serial': self.serialno,
            'refresh': self.refresh,
            'retry': self.retry,
            'expire': self.expire,
            'soa_ttl': self.soa_ttl,
            'zupdated_at': timezone.localtime(self.updated_at),
            'supdated_at': timezone.localtime(self.serialno_updated_at)
        }
        zf = """$ORIGIN {origin}
$TTL {default_ttl}
{name:30} IN {record_type:6} {mname} {rname} (
                                         {serial}    ; Serialnumber
                                         {refresh}   ; Refresh
                                         {retry}     ; Retry
                                         {expire}    ; Expire
                                         {soa_ttl} ) ; Negative Cache
; zone.updated_at: {zupdated_at}
; zone.serialno_updated_at: {supdated_at}
""".format_map(data)
        return zf

    def update_serialno(self, force=False):
        """Update serialno if zone has been updated since the serial number
        was updated.
        """
        # Need the have a timedelta as serialno_updated_at to not exhaust
        # the 1000 possible daily serial numbers.
        min_delta = timedelta(minutes=1)
        if force or self.updated and \
           timezone.now() > self.serialno_updated_at + min_delta:
            new_serial = create_serialno(self.serialno)
            # If hitting the daily limit, make sure not to change the
            # other variables.
            if new_serial == self.serialno:
                return
            self.serialno = new_serial
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

        def _get_reverse_order(data):
            """Return data with longest names first"""
            # We must sort the zones to assert that foo.example.org hosts
            # does not end up in the example.org zone.  This is achieved by
            # spelling the zone postfix backwards and sorting the resulting
            # list backwards
            lst = [str(x.name)[::-1] for x in data]
            t = range(len(lst))
            for i in sorted(t, key=lambda i: lst[i], reverse=True):
                yield data[i]

        zones = ForwardZone.objects.all()
        for zone in _get_reverse_order(zones):
            if zone.name == name:
                return zone
            elif name.endswith(f".{zone.name}"):
                return zone
        return None


class ReverseZone(BaseZone):
    name = DnsNameField(unique=True, validators=[validate_reverse_zone_name])
    # network can not be blank, but it will allow full_clean() to pass, even if
    # the network is not set. Will anyway be overridden by update() and save().
    network = CidrAddressField(unique=True, blank=True)

    objects = NetManager()

    class Meta:
        db_table = 'reverse_zone'

    def save(self, *args, **kwargs):
        self.network = get_network_from_zonename(self.name)
        super().save(*args, **kwargs)

    @staticmethod
    def get_zone_by_ip(ip):
        """Search and return a zone which contains an IP address."""
        return ReverseZone.objects.filter(network__net_contains=ip).first()

    def get_ipaddresses(self):
        """
        Get all ipaddresses used in a reverse zone.

        Will return tuples of (ipaddress, ttl, hostname), sorted by ipaddress.
        """
        network = self.network
        from_ip = str(network.network_address)
        to_ip = str(network.broadcast_address)
        ipaddresses = dict()
        override_ips = dict()
        for model, data in ((Ipaddress, ipaddresses),
                            (PtrOverride, override_ips),
                            ):
            qs = model.objects.filter(ipaddress__range=(from_ip, to_ip))
            for ip, ttl, hostname in qs.values_list('ipaddress', 'host__ttl', 'host__name'):
                data[ip] = (ttl, hostname)
        # XXX: send signal/mail to hostmaster(?) about issues with multiple_ip_no_ptr
        count = defaultdict(int)
        for i in ipaddresses:
            if i not in override_ips:
                count[i] += 1
        multiple_ip_no_ptr = {i: count[i] for i in count if count[i] > 1}
        ptr_done = set()
        result = []

        def _add_to_result(ip, ttl, hostname):
            # Wildcards are not allowed in reverse zones.
            if "*" in hostname:
                return
            ttl = ttl or ""
            result.append((ipaddress.ip_address(ip), ttl, hostname))

        # Use PtrOverrides when found, but only once. Also skip IPaddresses
        # which have been used multiple times, but lacks a PtrOverride.
        for ip, data in ipaddresses.items():
            if ip in multiple_ip_no_ptr:
                continue
            if ip in override_ips:
                if ip not in ptr_done:
                    ptr_done.add(ip)
                    _add_to_result(ip, *override_ips[ip])
            else:
                _add_to_result(ip, *data)
        # Add PtrOverrides which actually don't override anything,
        # but are only used as PTRs without any Ipaddress object creating
        # forward entries.
        for ptr, data in override_ips.items():
            if ptr not in ptr_done:
                _add_to_result(ptr, *data)

        # Return sorted by IP
        return sorted(result, key=lambda i: i[0])


class ForwardZoneDelegation(BaseModel, ZoneHelpers):
    zone = models.ForeignKey(ForwardZone, on_delete=models.CASCADE, db_column='zone',
                             related_name='delegations')
    name = DnsNameField(unique=True)
    nameservers = models.ManyToManyField(NameServer, db_column='ns')
    comment = models.CharField(blank=True, max_length=200)

    class Meta:
        db_table = 'forward_zone_delegation'

    def __str__(self):
        return f"{self.zone.name} {self.name}"


class ReverseZoneDelegation(BaseModel, ZoneHelpers):
    zone = models.ForeignKey(ReverseZone, on_delete=models.CASCADE, db_column='zone',
                             related_name='delegations')
    name = DnsNameField(unique=True, validators=[validate_reverse_zone_name])
    nameservers = models.ManyToManyField(NameServer, db_column='ns')
    comment = models.CharField(blank=True, max_length=200)

    class Meta:
        db_table = 'reverse_zone_delegation'

    def __str__(self):
        return f"{self.zone.name} {self.name}"


class ForwardZoneMember(BaseModel):
    zone = models.ForeignKey(ForwardZone, models.DO_NOTHING, db_column='zone',
                             blank=True, null=True)

    class Meta:
        abstract = True


class Host(ForwardZoneMember):
    name = DnsNameField(unique=True)
    contact = pgfields.CIEmailField(blank=True)
    ttl = models.IntegerField(blank=True, null=True, validators=[validate_ttl])
    comment = models.TextField(blank=True)

    class Meta:
        db_table = 'host'

    def __str__(self):
        return str(self.name)


class Loc(BaseModel):
    host = models.OneToOneField(Host, on_delete=models.CASCADE, primary_key=True)
    loc = models.TextField(validators=[validate_loc])

    class Meta:
        db_table = 'loc'

    def __str__(self):
        return f"{self.host.name} -> {self.loc}"


class Sshfp(BaseModel):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host')
    ttl = models.IntegerField(blank=True, null=True, validators=[validate_ttl])
    algorithm = models.IntegerField(choices=((1, 'RSA'), (2, 'DSS'), (3, 'ECDSA'),
                                             (4, 'Ed25519')))
    hash_type = models.IntegerField(choices=((1, 'SHA-1'), (2, 'SHA-256')))
    fingerprint = models.CharField(max_length=64, validators=[validate_hexadecimal])

    class Meta:
        db_table = 'sshfp'
        unique_together = (('host', 'algorithm', 'hash_type', 'fingerprint'), )

    def __str__(self):
        return (
            f"{self.host.name} -> {self.algorithm} ({self.get_algorithm_display()}) "
            f"{self.hash_type} ({self.get_hash_type_display()}) {self.fingerprint}"
        )


class Ipaddress(BaseModel):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host',
                             related_name='ipaddresses')
    ipaddress = models.GenericIPAddressField()
    macaddress = models.CharField(max_length=17, blank=True, validators=[validate_mac_address])

    class Meta:
        db_table = 'ipaddress'
        unique_together = (('host', 'ipaddress'), )

    def __str__(self):
        return "{} -> {}".format(str(self.ipaddress), str(self.macaddress) or "None")

    def delete(self, using=None, keep_parents=False):
        PtrOverride.objects.filter(host=self.host, ipaddress=self.ipaddress).delete()
        return super().delete(using=using, keep_parents=keep_parents)


class Hinfo(BaseModel):
    host = models.OneToOneField(Host, on_delete=models.CASCADE, primary_key=True)
    cpu = models.TextField()
    os = models.TextField()

    class Meta:
        db_table = 'hinfo'

    def __str__(self):
        return f"cpu: {self.cpu} os: {self.os}"


class Mx(BaseModel):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host',
                             related_name='mxs')
    priority = models.PositiveIntegerField(validators=[validate_16bit_uint])
    mx = DnsNameField()

    class Meta:
        db_table = 'mx'
        unique_together = ('host', 'priority', 'mx')

    def __str__(self):
        return f"{self.priority} {self.mx}"


class PtrOverride(BaseModel):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host',
                             related_name='ptr_overrides')
    ipaddress = models.GenericIPAddressField(unique=True)

    class Meta:
        db_table = 'ptr_override'

    def __str__(self):
        return "{} -> {}".format(str(self.ipaddress), str(self.host.name))


class Txt(BaseModel):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host',
                             related_name='txts')
    txt = models.TextField(max_length=255)

    class Meta:
        db_table = 'txt'
        unique_together = ('host', 'txt')

    def __str__(self):
        return str(self.txt)


class Cname(ForwardZoneMember):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host',
                             related_name='cnames')
    name = DnsNameField(unique=True)
    ttl = models.IntegerField(blank=True, null=True, validators=[validate_ttl])

    class Meta:
        db_table = 'cname'
        ordering = ('name',)

    def __str__(self):
        return "{} -> {}".format(str(self.name), str(self.host))


MAX_UNUSED_LIST = 4096  # 12 bits for addresses. A large ipv4, but tiny ipv6 network.


class Network(BaseModel):
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

    def save(self, *args, **kwargs):
        if isinstance(self.network, str):
            network = ipaddress.ip_network(self.network)
        else:
            network = self.network

        if self.reserved > network.num_addresses:
            self.reserved = network.num_addresses
        super().save(*args, **kwargs)

    def get_reserved_ipaddresses(self):
        """ Returns a set with the reserved ip addresses for the network."""
        network = self.network
        ret = set([network.network_address])
        for i, ip in zip(range(self.reserved), network.hosts()):
            ret.add(ip)
        if isinstance(network, ipaddress.IPv4Network):
            ret.add(network.broadcast_address)
        return ret

    def get_unusable_ipaddresses(self):
        """ Returns a set with all ips which can not be used:
            - reserved addresses
            - ips in excluded ranges
        """
        unusable = self.get_reserved_ipaddresses()
        for i in self.excluded_ranges.all():
            ip = ipaddress.ip_address(i.start_ip)
            end_ip = ipaddress.ip_address(i.end_ip)
            while ip <= end_ip:
                unusable.add(ip)
                ip += 1
        return unusable

    def _get_used_ipaddresses(self):
        from_ip = str(self.network.network_address)
        to_ip = str(self.network.broadcast_address)
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
        unusable = self.get_unusable_ipaddresses()
        used = self.get_used_ipaddresses()
        not_available = unusable | used
        if self.network.num_addresses > MAX_UNUSED_LIST:
            # Getting all availible IPs for a ipv6 prefix can easily cause
            # the webserver to hang due to lots and lots of IPs. Instead limit
            # to the first MAX_UNUSED_LIST hosts.
            found = 0
            for ip in self.network.hosts():
                if ip in not_available:
                    continue
                network_ips.append(ip)
                found += 1
                if found == MAX_UNUSED_LIST:
                    break
            return set(network_ips)
        else:
            return set(self.network.hosts()) - not_available

    def get_unused_ipaddress_count(self):
        """
        Returns the number of unused ipaddreses on the network.
        """
        unusable = self.get_unusable_ipaddresses()
        used = self.get_used_ipaddresses()
        return self.network.num_addresses - len(unusable | used)

    def get_first_unused(self):
        """
        Return the first unused IP found, if any.
        """

        unusable = self.get_unusable_ipaddresses()
        used = self.get_used_ipaddresses()
        for ip in self.network.hosts():
            if ip in unusable:
                continue
            if ip not in used:
                return str(ip)
        return None

    def get_random_unused(self):
        """
        Return a random unused IP, if any.
        """

        unused = self.get_unused_ipaddresses()
        if unused:
            network = self.network
            if len(unused) == MAX_UNUSED_LIST and network.num_addresses > MAX_UNUSED_LIST:
                # Attempt to use the entire address if encountering a network larger
                # than MAX_UNUSED_LIST. Typically an IPv6 network.
                network_address = int(network.network_address)
                broadcast_address = int(network.broadcast_address)
                unusable = self.get_unusable_ipaddresses()
                used = self.get_used_ipaddresses()
                not_available = unusable | used
                # Limit the number of attempts, as random might be really unlucky.
                for attempts in range(100):
                    choice = random.randint(network_address, broadcast_address)
                    if network.version == 6:
                        randomip = ipaddress.IPv6Address(choice)
                    else:
                        randomip = ipaddress.IPv4Address(choice)
                    if randomip not in not_available:
                        return str(randomip)

            return str(random.choice(tuple(unused)))

        return None


class NetworkExcludedRange(BaseModel):
    """
    Exclude all usage ip adresses between start and end IP address for a network.
    """
    network = models.ForeignKey(Network, on_delete=models.CASCADE, db_column='excluded_range',
                                related_name='excluded_ranges')
    start_ip = models.GenericIPAddressField(unique=True)
    end_ip = models.GenericIPAddressField(unique=True)

    class Meta:
        db_table = 'network_exluded_range'
        ordering = ('start_ip', )

    def __str__(self):
        return f'{self.network.network} -> [{self.start_ip} -> [{self.end_ip}]'


class Naptr(BaseModel):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host',
                             related_name='naptrs')
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
    # This field is called "Target" in the RFC, but to utilize other code we
    # name a field with foreignKey to Host as "host".
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column='host',
                             related_name='srvs')

    class Meta:
        db_table = 'srv'
        unique_together = ('name', 'priority', 'weight', 'port', 'host')
        ordering = ('name', 'priority', 'weight', 'port', 'host')

    def __str__(self):
        return str(self.name)


class HostGroup(BaseModel):
    name = LCICharField(max_length=50, unique=True)
    description = models.CharField(max_length=200, blank=True)
    owners = models.ManyToManyField(Group, blank=True)
    parent = models.ManyToManyField('self', symmetrical=False, blank=True,
                                    related_name='groups')
    hosts = models.ManyToManyField(Host, related_name='hostgroups')

    class Meta:
        db_table = 'hostgroup'
        ordering = ('name',)

    def __str__(self):
        return "%s" % self.name


class NetGroupRegexPermission(BaseModel):
    group = models.CharField(max_length=80)
    range = CidrAddressField()
    regex = models.CharField(max_length=250, validators=[validate_regex])

    objects = NetManager()

    class Meta:
        db_table = 'perm_net_group_regex'
        unique_together = ('group', 'range', 'regex', )

    def __str__(self):
        return f"group {self.group}, range {self.range}, regex {self.regex}"

    @classmethod
    def find_perm(cls, groups, hostname, ips):
        if not isinstance(hostname, str):
            raise ValueError(f'hostname is invalid type ({type(hostname)})')
        if isinstance(groups, str):
            groups = [groups]
        if not isinstance(groups, (list, tuple)):
            raise ValueError(f'groups on invalid type ({type(groups)})')
        if isinstance(ips, str):
            ips = [ips]
        if not isinstance(ips, (list, tuple)):
            raise ValueError(f'ips on invalid type ({type(ips)})')
        if not all([groups, hostname, ips]):
            return cls.objects.none()
        qs = cls.objects.filter(
                group__in=groups
            ).extra(
                where=["%s ~ regex"], params=[str(hostname)]
            ).filter(
                reduce(lambda x, y: x | y, [Q(range__net_contains=ip) for ip in ips])
            )
        return qs


class History(models.Model):
    """
    Store history for various models.

    Use the resource field to set the scope for each group of events.
    """
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.CharField(max_length=64)
    resource = models.CharField(max_length=64)
    name = models.CharField(max_length=255)
    model_id = models.PositiveIntegerField()
    model = models.CharField(max_length=64)
    action = models.CharField(max_length=64)
    data = pgfields.JSONField()

    def __str__(self):
        return f'{self.name}, {self.model}, {self.action}, {self.timestamp}'
