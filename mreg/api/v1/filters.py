from django_filters import rest_framework as filters

from mreg.models.base import History
from mreg.models.host import BACnetID, Host, HostGroup, Ipaddress, PtrOverride
from mreg.models.network import (
    Label,
    NetGroupRegexPermission,
    Network,
    NetworkExcludedRange,
)
from mreg.models.resource_records import Cname, Hinfo, Loc, Mx, Naptr, Srv, Sshfp, Txt
from mreg.models.zone import (
    ForwardZone,
    ForwardZoneDelegation,
    NameServer,
    ReverseZone,
    ReverseZoneDelegation,
)

class FilterWithID(filters.FilterSet):
    id = filters.NumberFilter(field_name="id")
    id__in = filters.BaseInFilter(field_name="id")
    id__gt = filters.NumberFilter(field_name="id", lookup_expr="gt")
    id__lt = filters.NumberFilter(field_name="id", lookup_expr="lt")


class JSONFieldExactFilter(filters.CharFilter):
    pass


class CIDRFieldExactFilter(filters.CharFilter):
    pass


class BACnetIDFilterSet(FilterWithID):
    class Meta:
        model = BACnetID
        fields = "__all__"


class CnameFilterSet(FilterWithID):
    class Meta:
        model = Cname
        fields = "__all__"


class ForwardZoneFilterSet(FilterWithID):
    class Meta:
        model = ForwardZone
        fields = "__all__"


class ForwardZoneDelegationFilterSet(FilterWithID):
    class Meta:
        model = ForwardZoneDelegation
        fields = "__all__"


class HinfoFilterSet(FilterWithID):
    class Meta:
        model = Hinfo
        fields = "__all__"


class HistoryFilterSet(FilterWithID):
    data = JSONFieldExactFilter(field_name="data")

    class Meta:
        model = History
        fields = "__all__"


class HostFilterSet(FilterWithID):
    class Meta:
        model = Host
        fields = "__all__"


class HostGroupFilterSet(FilterWithID):
    class Meta:
        model = HostGroup
        fields = "__all__"


class IpaddressFilterSet(FilterWithID):
    class Meta:
        model = Ipaddress
        fields = "__all__"


class LabelFilterSet(FilterWithID):
    class Meta:
        model = Label
        fields = "__all__"


class LocFilterSet(FilterWithID):
    class Meta:
        model = Loc
        fields = "__all__"


class MxFilterSet(FilterWithID):
    class Meta:
        model = Mx
        fields = "__all__"


class NameServerFilterSet(FilterWithID):
    class Meta:
        model = NameServer
        fields = "__all__"


class NaptrFilterSet(FilterWithID):
    class Meta:
        model = Naptr
        fields = "__all__"


class NetGroupRegexPermissionFilterSet(FilterWithID):
    range = CIDRFieldExactFilter(field_name="range")

    class Meta:
        model = NetGroupRegexPermission
        fields = "__all__"


class NetworkFilterSet(FilterWithID):
    network = CIDRFieldExactFilter(field_name="network")

    class Meta:
        model = Network
        fields = "__all__"


class NetworkExcludedRangeFilterSet(FilterWithID):
    class Meta:
        model = NetworkExcludedRange
        fields = "__all__"


class PtrOverrideFilterSet(FilterWithID):
    class Meta:
        model = PtrOverride
        fields = "__all__"


class ReverseZoneFilterSet(FilterWithID):
    network = CIDRFieldExactFilter(field_name="network")

    class Meta:
        model = ReverseZone
        fields = "__all__"


class ReverseZoneDelegationFilterSet(FilterWithID):
    class Meta:
        model = ReverseZoneDelegation
        fields = "__all__"

class SrvFilterSet(FilterWithID):
    class Meta:
        model = Srv
        fields = "__all__"


class SshfpFilterSet(FilterWithID):
    class Meta:
        model = Sshfp
        fields = "__all__"


class TxtFilterSet(FilterWithID):
    class Meta:
        model = Txt
        fields = "__all__"
