import ipaddress
import random
from functools import reduce

from django.db import models
from django.db.models import Q
from netfields import CidrAddressField, NetManager

from mreg.models.base import MAX_UNUSED_LIST, BaseModel, Label
from mreg.models.network_policy import NetworkPolicy
from mreg.validators import validate_regex


class Network(BaseModel):
    network = CidrAddressField(unique=True)
    description = models.TextField(blank=True)
    vlan = models.IntegerField(blank=True, null=True)
    dns_delegated = models.BooleanField(default=False)
    category = models.TextField(blank=True)
    location = models.TextField(blank=True)
    frozen = models.BooleanField(default=False)
    reserved = models.PositiveIntegerField(default=3)

    policy = models.ForeignKey(
        NetworkPolicy,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='networks',
        help_text="Optional policy applied to the network."
    )

    objects = NetManager()

    class Meta:
        db_table = "network"
        ordering = ("network",)

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
        """Returns a set with the reserved ip addresses for the network."""
        network = self.network
        ret = set([network.network_address])
        for i, ip in zip(range(self.reserved), network.hosts()):
            ret.add(ip)
        if isinstance(network, ipaddress.IPv4Network):
            ret.add(network.broadcast_address)
        return ret

    def get_excluded_ranges_start_end(self):
        excluded = []
        for start_ip, end_ip in self.excluded_ranges.values_list("start_ip", "end_ip"):
            start_ip = ipaddress.ip_address(start_ip)
            end_ip = ipaddress.ip_address(end_ip)
            excluded.append((start_ip, end_ip))
        return excluded

    def get_unused_ipaddresses(self, max=MAX_UNUSED_LIST):
        """
        Returns which ipaddresses on the network are unused.
        """
        network_ips = []
        used_or_reserved = self.used_addresses | self.get_reserved_ipaddresses()
        excluded = self.get_excluded_ranges_start_end()
        # Getting all available IPs for a ipv6 prefix can easily cause
        # the webserver to hang due to lots and lots of IPs. Instead limit
        # to the first MAX_UNUSED_LIST hosts.
        found = 0
        ip = next(self.network.hosts())
        while ip in self.network:
            if ip in used_or_reserved:
                ip += 1
                continue
            was_excluded = False
            for start_ip, end_ip in excluded:
                if ip >= start_ip and ip <= end_ip:
                    ip = end_ip + 1
                    was_excluded = True
            if was_excluded:
                continue
            network_ips.append(ip)
            found += 1
            if found == max:
                break
            ip += 1
        return set(network_ips)

    def __used(self, model):
        from_ip = str(self.network.network_address)
        to_ip = str(self.network.broadcast_address)
        return model.objects.filter(ipaddress__range=(from_ip, to_ip))

    @staticmethod
    def __used_ips(qs):
        ips = qs.values_list("ipaddress", flat=True)
        return {ipaddress.ip_address(ip) for ip in ips}

    def _used_ipaddresses(self):
        from mreg.models.host import Ipaddress

        return self.__used(Ipaddress)

    def _used_ptroverrides(self):
        from mreg.models.host import PtrOverride

        return self.__used(PtrOverride)

    @property
    def used_ipaddresses(self):
        """
        Returns the used Ipaddress objects on the network.
        """
        return self.__used_ips(self._used_ipaddresses())

    @property
    def used_ptroverrides(self):
        return self.__used_ips(self._used_ptroverrides())

    @property
    def used_addresses(self):
        """
        Returns which ipaddresses on the network are used.

        A combined usage of Ipaddress and PtrOverride.
        """
        return self.used_ipaddresses | self.used_ptroverrides

    @property
    def unused_addresses(self):
        """
        Returns which ipaddresses on the network are unused.
        """
        return self.get_unused_ipaddresses()

    @property
    def unused_count(self):
        """
        Returns the number of unused ipaddresses on the network.
        """
        # start with the number of all adresses defined by the CIDR
        result = self.network.num_addresses
        # subtract excluded ranges
        for i in self.excluded_ranges.all():
            result -= i.num_addresses()
        # subtract used and reserved addresses
        used_or_reserved = self.used_addresses | self.get_reserved_ipaddresses()
        result -= len(used_or_reserved)
        return result

    def get_first_unused(self):
        """
        Return the first unused IP found, if any.
        """
        a = self.get_unused_ipaddresses(1)
        if a:
            return str(next(iter(a)))
        return None

    def get_random_unused(self):
        """
        Return a random unused IP, if any.
        """

        unused = self.unused_addresses
        if unused:
            network = self.network
            if (
                len(unused) == MAX_UNUSED_LIST
                and network.num_addresses > MAX_UNUSED_LIST
            ):
                # Attempt to use the entire address if encountering a network larger
                # than MAX_UNUSED_LIST. Typically an IPv6 network.
                network_address = int(network.network_address)
                broadcast_address = int(network.broadcast_address)
                used_or_reserved = self.used_addresses | self.get_reserved_ipaddresses()
                excluded = self.get_excluded_ranges_start_end()
                # Limit the number of attempts, as random might be really unlucky.
                for attempts in range(100):
                    choice = random.randint(network_address, broadcast_address)
                    if network.version == 6:
                        randomip = ipaddress.IPv6Address(choice)
                    else:
                        randomip = ipaddress.IPv4Address(choice)
                    if randomip in used_or_reserved:
                        continue
                    was_excluded = False
                    for start_ip, end_ip in excluded:
                        if randomip >= start_ip and randomip <= end_ip:
                            was_excluded = True
                            break
                    if was_excluded:
                        continue
                    return str(randomip)

            return str(random.choice(tuple(unused)))

        return None


class NetworkExcludedRange(BaseModel):
    """
    Exclude all usage ip adresses between start and end IP address for a network.
    """

    network = models.ForeignKey(
        Network,
        on_delete=models.CASCADE,
        db_column="excluded_range",
        related_name="excluded_ranges",
    )
    start_ip = models.GenericIPAddressField(unique=True)
    end_ip = models.GenericIPAddressField(unique=True)

    class Meta:
        db_table = "network_exluded_range"
        ordering = ("start_ip",)

    def __str__(self):
        return f"{self.network.network} -> [{self.start_ip} -> [{self.end_ip}]"

    def num_addresses(self):
        start = ipaddress.ip_address(self.start_ip)
        end = ipaddress.ip_address(self.end_ip)
        return int(end) - int(start) + 1


class NetGroupRegexPermission(BaseModel):
    group = models.CharField(max_length=80)
    range = CidrAddressField()
    regex = models.CharField(max_length=250, validators=[validate_regex])
    labels = models.ManyToManyField(Label, blank=True, related_name="permissions")

    objects = NetManager()

    class Meta:
        db_table = "perm_net_group_regex"
        unique_together = (
            "group",
            "range",
            "regex",
        )

    def __str__(self):
        return f"group {self.group}, range {self.range}, regex {self.regex}"

    @classmethod
    def find_perm(cls, groups, hostname, ips, require_ip=True):
        if not isinstance(hostname, str):
            raise ValueError(f"hostname is invalid type ({type(hostname)})")
        if isinstance(groups, str):
            groups = [groups]
        if not isinstance(groups, (list, tuple)):
            raise ValueError(f"groups on invalid type ({type(groups)})")
        if isinstance(ips, str):
            ips = [ips]
        if not isinstance(ips, (list, tuple)):
            raise ValueError(f"ips on invalid type ({type(ips)})")
        if require_ip and not ips:
            return cls.objects.none()
        if not all([groups, hostname]):
            return cls.objects.none()
        qs = cls.objects.filter(group__in=groups).extra(
            where=["%s ~ regex"], params=[str(hostname)]
        )
        if require_ip:
            qs = qs.filter(
                reduce(lambda x, y: x | y, [Q(range__net_contains=ip) for ip in ips])
            )
        return qs
