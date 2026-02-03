import ipaddress
from collections import defaultdict, namedtuple
from datetime import timedelta

from django.db import DatabaseError, models, transaction
from django.utils import timezone
from netfields import CidrAddressField, NetManager

from mreg.fields import LowerCaseDNSNameField
from mreg.managers import LowerCaseManager, lower_case_manager_factory
from mreg.models.base import BaseModel, NameServer, ZoneHelpers
from mreg.models.host import Ipaddress, PtrOverride
from mreg.utils import create_serialno, encode_mail, get_network_from_zonename, idna_encode, qualify
from mreg.validators import validate_32bit_uint, validate_reverse_zone_name, validate_ttl


class BaseZone(BaseModel, ZoneHelpers):
    updated = models.BooleanField(default=True)
    primary_ns = LowerCaseDNSNameField()
    nameservers = models.ManyToManyField(NameServer, db_column="ns")
    email = models.EmailField()
    serialno = models.BigIntegerField(default=create_serialno, validators=[validate_32bit_uint])
    serialno_updated_at = models.DateTimeField(default=timezone.now)
    refresh = models.IntegerField(default=10800)
    retry = models.IntegerField(default=3600)
    expire = models.IntegerField(default=1814400)
    soa_ttl = models.IntegerField(default=43200, validators=[validate_ttl])
    default_ttl = models.IntegerField(default=43200, validators=[validate_ttl])

    objects = LowerCaseManager()

    class Meta:
        abstract = True

    def __str__(self):
        return str(self.name)

    @property
    def zf_string(self):
        """String representation for zonefile export."""
        data = {
            "origin": idna_encode(qualify(self.name, self.name, shortform=False)),
            "default_ttl": self.default_ttl,
            "name": "@",
            "record_type": "SOA",
            "mname": idna_encode(qualify(self.primary_ns, self.name, shortform=False)),
            "rname": idna_encode(encode_mail(self.email)),
            "serial": self.serialno,
            "refresh": self.refresh,
            "retry": self.retry,
            "expire": self.expire,
            "soa_ttl": self.soa_ttl,
            "zupdated_at": timezone.localtime(self.updated_at),
            "supdated_at": timezone.localtime(self.serialno_updated_at),
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
        if force or self.updated and timezone.now() > self.serialno_updated_at + min_delta:
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
            except DatabaseError:  # pragma: no cover
                pass


class ForwardZone(BaseZone):
    name = LowerCaseDNSNameField(unique=True)

    objects = LowerCaseManager()

    class Meta:
        db_table = "forward_zone"

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
    name = LowerCaseDNSNameField(unique=True, validators=[validate_reverse_zone_name])
    # network can not be blank, but it will allow full_clean() to pass, even if
    # the network is not set. Will anyway be overridden by update() and save().
    network = CidrAddressField(unique=True, blank=True)

    # We want lower case filtering and exludes for "name", but also use NetManager for the network field.
    objects = lower_case_manager_factory(NetManager)()

    class Meta:
        db_table = "reverse_zone"

    def save(self, *args, **kwargs):
        self.network = get_network_from_zonename(self.name)
        super().save(*args, **kwargs)

    @staticmethod
    def get_zone_by_ip(ip):
        """Search and return a zone which contains an IP address."""
        return ReverseZone.objects.filter(network__net_contains=ip).first()

    def _get_excluded_ranges(self):
        """
        Get ranges which should not be exported in the reverse zone.

        These are addresses used by sub zones or delegations.

        Returned as a list of named tuples.
        """
        excluded_ips = list()
        Range = namedtuple("Range", "name from_ip to_ip")
        networks = list()
        for i in self.delegations.all():
            networks.append(get_network_from_zonename(i.name))
        for i in ReverseZone.objects.filter(name__endswith="." + self.name):
            networks.append(i.network)

        for network in networks:
            from_ip = str(network.network_address)
            to_ip = str(network.broadcast_address)
            excluded_ips.append(Range(name=str(network), from_ip=from_ip, to_ip=to_ip))

        return excluded_ips

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
        excluded_ranges = self._get_excluded_ranges()
        for model, data in (
            (Ipaddress, ipaddresses),
            (PtrOverride, override_ips),
        ):
            qs = model.objects.filter(ipaddress__range=(from_ip, to_ip))
            for exclude in excluded_ranges:
                qs = qs.exclude(ipaddress__range=(exclude.from_ip, exclude.to_ip))
            for ip, ttl, hostname in qs.values_list("ipaddress", "host__ttl", "host__name"):
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
            # Defensive: skip IPs without PtrOverride that appear multiple times.
            # In normal operation, signals automatically create PtrOverride for duplicate IPs,
            # so this branch is only hit if signals are disabled or fail.
            if ip in multiple_ip_no_ptr:  # pragma: no cover
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
    zone = models.ForeignKey(
        ForwardZone,
        on_delete=models.CASCADE,
        db_column="zone",
        related_name="delegations",
    )
    name = LowerCaseDNSNameField(unique=True)
    nameservers = models.ManyToManyField(NameServer, db_column="ns")
    comment = models.CharField(blank=True, max_length=200)

    objects = LowerCaseManager()

    class Meta:
        db_table = "forward_zone_delegation"

    def __str__(self):
        return f"{self.zone.name} {self.name}"


class ReverseZoneDelegation(BaseModel, ZoneHelpers):
    zone = models.ForeignKey(
        ReverseZone,
        on_delete=models.CASCADE,
        db_column="zone",
        related_name="delegations",
    )
    name = LowerCaseDNSNameField(unique=True, validators=[validate_reverse_zone_name])
    nameservers = models.ManyToManyField(NameServer, db_column="ns")
    comment = models.CharField(blank=True, max_length=200)

    class Meta:
        db_table = "reverse_zone_delegation"

    def __str__(self):
        return f"{self.zone.name} {self.name}"
