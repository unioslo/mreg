import operator
from functools import reduce
from typing import List

import structlog
from django.db.models import Q
from django_filters import rest_framework as filters
from rest_framework import exceptions

from mreg.models.base import History
from mreg.models.host import BACnetID, Host, HostGroup, Ipaddress, PtrOverride
from mreg.models.network import (Label, NetGroupRegexPermission, Network,
                                 NetworkExcludedRange)
from mreg.models.resource_records import (Cname, Hinfo, Loc, Mx, Naptr, Srv,
                                          Sshfp, Txt)
from mreg.models.zone import (ForwardZone, ForwardZoneDelegation, NameServer,
                              ReverseZone, ReverseZoneDelegation)
from mreg.models.policy import ApprovedModelForPolicy

from netaddr import IPNetwork, AddrFormatError

mreg_log = structlog.getLogger(__name__)

OperatorList = List[str]

STRING_OPERATORS: OperatorList = [
    "exact",
    "iexact",
    "regex",
    "contains",
    "icontains",
    "startswith",
    "istartswith",
    "endswith",
    "iendswith",
]
INT_OPERATORS: OperatorList = ["exact", "in", "gt", "lt"]
EXACT_OPERATORS: OperatorList = ["exact"]

HOST_FIELDS = {
    "host": INT_OPERATORS,
    "host__comment": STRING_OPERATORS,
    "host__contact": STRING_OPERATORS,
    "host__name": STRING_OPERATORS,
    "host__ttl": INT_OPERATORS,
}

CREATED_UPDATED = {
    "created_at": INT_OPERATORS,
    "updated_at": INT_OPERATORS,
}
class CIDRFieldFilter(filters.CharFilter):
    def filter(self, qs, value):
        if not value:
            return qs

        try:
            cidr = IPNetwork(value)
            return qs.filter(**{f"{self.field_name}__net_contains_or_equals": str(cidr)})
        except AddrFormatError:
            raise exceptions.ValidationError(f"Invalid CIDR: {value}")

class BACnetIDFilterSet(filters.FilterSet):
    class Meta:
        model = BACnetID
        fields = {
            "id": INT_OPERATORS,
            **HOST_FIELDS,
        }


class CnameFilterSet(filters.FilterSet):
    class Meta:
        model = Cname
        fields = {
            "id": INT_OPERATORS,
            "name": STRING_OPERATORS,
            "ttl": INT_OPERATORS,
            **HOST_FIELDS,
            **CREATED_UPDATED,
        }


class ForwardZoneFilterSet(filters.FilterSet):
    class Meta:
        model = ForwardZone
        fields = {
            "id": INT_OPERATORS,
            "name": STRING_OPERATORS,
            **CREATED_UPDATED,
        }


class ForwardZoneDelegationFilterSet(filters.FilterSet):
    class Meta:
        model = ForwardZoneDelegation
        fields = {
            "id": INT_OPERATORS,
            "name": STRING_OPERATORS,
            "nameservers": INT_OPERATORS,
            "comment": STRING_OPERATORS,
            **CREATED_UPDATED,
        }


class HinfoFilterSet(filters.FilterSet):
    class Meta:
        model = Hinfo
        fields = {
            "cpu": STRING_OPERATORS,
            "host": INT_OPERATORS,
            "os": STRING_OPERATORS,
        }


class HistoryFilterSet(filters.FilterSet):
    class Meta:
        model = History
        fields = {
            "id": INT_OPERATORS,
            "timestamp": INT_OPERATORS,
            "user": STRING_OPERATORS,
            "resource": STRING_OPERATORS,
            "name": STRING_OPERATORS,
            "model_id": INT_OPERATORS,
            "model": STRING_OPERATORS,
            "action": STRING_OPERATORS,
        }

    # This is a fugly hack to make JSON filtering "work"
    def filter_queryset(self, queryset):
        data_filters = {k: v for k, v in self.data.items() if k.startswith("data__")}

        if data_filters:
            queries = []
            for key, value in data_filters.items():
                json_key = key.split("data__")[1]
                if "__in" in json_key:
                    json_key = json_key.split("__in")[0]
                    values = value.split(",")
                    queries.append(Q(**{f"data__{json_key}__in": values}))
                else:
                    queries.append(Q(**{f"data__{json_key}": value}))

            queryset = queryset.filter(reduce(operator.and_, queries))

        return super().filter_queryset(queryset)


class HostFilterSet(filters.FilterSet):
    class Meta:
        model = Host
        fields = {
            "id": INT_OPERATORS,
            "name": STRING_OPERATORS,
            "contact": STRING_OPERATORS,
            "ttl": INT_OPERATORS,
            "comment": STRING_OPERATORS,
            # These are related fields, ie, inverse relationships
            "ipaddresses": INT_OPERATORS,
            "ipaddresses__ipaddress": EXACT_OPERATORS,
            "ipaddresses__macaddress": STRING_OPERATORS,
            "ptr_overrides": INT_OPERATORS,
            "ptr_overrides__ipaddress": EXACT_OPERATORS,
            "hostgroups": INT_OPERATORS,
            "hostgroups__name": STRING_OPERATORS,
            "hostgroups__description": STRING_OPERATORS,
            "bacnetid": INT_OPERATORS,
            "mxs": INT_OPERATORS,
            "mxs__priority": INT_OPERATORS,
            "mxs__mx": STRING_OPERATORS,
            "txts": INT_OPERATORS,
            "txts__txt": STRING_OPERATORS,
            "cnames": INT_OPERATORS,
            "cnames__name": STRING_OPERATORS,
            "cnames__ttl": INT_OPERATORS,
            "naptrs": INT_OPERATORS,
            "naptrs__order": INT_OPERATORS,
            "naptrs__preference": INT_OPERATORS,
            "naptrs__flag": STRING_OPERATORS,
            "naptrs__service": STRING_OPERATORS,
            "naptrs__regex": STRING_OPERATORS,
            "naptrs__replacement": STRING_OPERATORS,
            "srvs": INT_OPERATORS,
            "srvs__name": STRING_OPERATORS,
            "srvs__priority": INT_OPERATORS,
            "srvs__weight": INT_OPERATORS,
            "srvs__port": INT_OPERATORS,
            "srvs__ttl": INT_OPERATORS,
            **CREATED_UPDATED,
        }


class HostGroupFilterSet(filters.FilterSet):
    class Meta:
        model = HostGroup
        fields = {
            "id": INT_OPERATORS,
            "description": STRING_OPERATORS,
            "hosts": INT_OPERATORS,
            "name": STRING_OPERATORS,
            "owners": INT_OPERATORS,
            "parent": INT_OPERATORS,
            **CREATED_UPDATED,
        }


class IpaddressFilterSet(filters.FilterSet):
    class Meta:
        model = Ipaddress
        fields = {
            "id": INT_OPERATORS,
            "ipaddress": STRING_OPERATORS,
            "macaddress": STRING_OPERATORS,
            **HOST_FIELDS,
        }


class LabelFilterSet(filters.FilterSet):
    class Meta:
        model = Label
        fields = {
            "id": INT_OPERATORS,
            "description": STRING_OPERATORS,
            "name": STRING_OPERATORS,
            **CREATED_UPDATED,
        }


class LocFilterSet(filters.FilterSet):
    class Meta:
        model = Loc
        fields = {
            "loc": STRING_OPERATORS,
            **HOST_FIELDS,
        }


class MxFilterSet(filters.FilterSet):
    class Meta:
        model = Mx
        fields = {
            "id": INT_OPERATORS,
            "priority": INT_OPERATORS,
            "mx": STRING_OPERATORS,
            **HOST_FIELDS,
            **CREATED_UPDATED
        }


class NameServerFilterSet(filters.FilterSet):
    class Meta:
        model = NameServer
        fields = {
            "id": INT_OPERATORS,
            "name": STRING_OPERATORS,
            "ttl": INT_OPERATORS,
            **CREATED_UPDATED,
        }


class NaptrFilterSet(filters.FilterSet):
    class Meta:
        model = Naptr
        fields = {
            "id": INT_OPERATORS,
            "preference": INT_OPERATORS,
            "order": INT_OPERATORS,
            "flag": STRING_OPERATORS,
            "service": STRING_OPERATORS,
            "regex": STRING_OPERATORS,
            "replacement": STRING_OPERATORS,
            **HOST_FIELDS,
            **CREATED_UPDATED,
        }


class NetGroupRegexPermissionFilterSet(filters.FilterSet):
    range = CIDRFieldFilter(field_name="range")

    class Meta:
        model = NetGroupRegexPermission
        fields = {
            "id": INT_OPERATORS,
            "group": STRING_OPERATORS,
            "regex": STRING_OPERATORS,
            "labels": INT_OPERATORS,
            **CREATED_UPDATED,
        }


class NetworkFilterSet(filters.FilterSet):
    network = CIDRFieldFilter(field_name="network")

    class Meta:
        model = Network
        fields = {
            "id": INT_OPERATORS,
            "description": STRING_OPERATORS,
            "vlan": INT_OPERATORS,
            "dns_delegated": EXACT_OPERATORS,
            "category": STRING_OPERATORS,
            "location": STRING_OPERATORS,
            "frozen": EXACT_OPERATORS,
            "reserved": INT_OPERATORS,
            **CREATED_UPDATED,
        }


class NetworkExcludedRangeFilterSet(filters.FilterSet):
    class Meta:
        model = NetworkExcludedRange
        fields = {
            "id": INT_OPERATORS,
            "network": INT_OPERATORS,
            "network__description": STRING_OPERATORS,
            "network__vlan": INT_OPERATORS,
            "network__dns_delegated": EXACT_OPERATORS,
            "network__category": STRING_OPERATORS,
            "network__location": STRING_OPERATORS,
            "network__frozen": EXACT_OPERATORS,
            "network__reserved": INT_OPERATORS,
            "start_ip": STRING_OPERATORS,
            "end_ip": STRING_OPERATORS,
            **CREATED_UPDATED,
        }


class PtrOverrideFilterSet(filters.FilterSet):
    class Meta:
        model = PtrOverride
        fields = {
            "id": INT_OPERATORS,
            "ipaddress": EXACT_OPERATORS,
            **HOST_FIELDS,
            **CREATED_UPDATED,
        }



class ReverseZoneFilterSet(filters.FilterSet):
    network = CIDRFieldFilter(field_name="network")

    class Meta:
        model = ReverseZone
        fields = {
            "id": INT_OPERATORS,
            "name": STRING_OPERATORS,
            **CREATED_UPDATED,
        }


class ReverseZoneDelegationFilterSet(filters.FilterSet):
    class Meta:
        model = ReverseZoneDelegation
        fields = {
            "id": INT_OPERATORS,
            "name": STRING_OPERATORS,
            "nameservers": INT_OPERATORS,
            "comment": STRING_OPERATORS,
            "zone": INT_OPERATORS,
            "zone__name": STRING_OPERATORS,
            **CREATED_UPDATED,
        }


class SrvFilterSet(filters.FilterSet):
    class Meta:
        model = Srv
        fields = {
            "id": INT_OPERATORS,
            "name": STRING_OPERATORS,
            "priority": INT_OPERATORS,
            "weight": INT_OPERATORS,
            "port": INT_OPERATORS,
            "ttl": INT_OPERATORS,
            **HOST_FIELDS,
            **CREATED_UPDATED,
        }


class SshfpFilterSet(filters.FilterSet):
    class Meta:
        model = Sshfp
        fields = {
            "id": INT_OPERATORS,
            "algorithm": INT_OPERATORS,
            "hash_type": INT_OPERATORS,
            "fingerprint": STRING_OPERATORS,
            **HOST_FIELDS,
            **CREATED_UPDATED,
        }


class TxtFilterSet(filters.FilterSet):
    class Meta:
        model = Txt
        fields = {
            "id": INT_OPERATORS,
            "txt": STRING_OPERATORS,
            **HOST_FIELDS,
            **CREATED_UPDATED,
        }

class ApprovedModelFilterSet(filters.FilterSet):
    content_type = filters.CharFilter(field_name="content_type__model", lookup_expr="iexact")
    content_type__exact = filters.CharFilter(field_name="content_type__model", lookup_expr="iexact")
    content_type__contains = filters.CharFilter(field_name="content_type__model", lookup_expr="icontains")
    content_type__regex = filters.CharFilter(field_name="content_type__model", lookup_expr="regex")    

    class Meta:
        model = ApprovedModelForPolicy
        fields = {
            "id": INT_OPERATORS,
        }