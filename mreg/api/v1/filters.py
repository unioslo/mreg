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


class JSONFieldExactFilter(filters.CharFilter):
    pass


class CIDRFieldExactFilter(filters.CharFilter):
    pass


class BACnetIDFilterSet(filters.FilterSet):
    class Meta:
        model = BACnetID
        fields = "__all__"


class CnameFilterSet(filters.FilterSet):
    class Meta:
        model = Cname
        fields = "__all__"


class ForwardZoneFilterSet(filters.FilterSet):
    class Meta:
        model = ForwardZone
        fields = "__all__"


class ForwardZoneDelegationFilterSet(filters.FilterSet):
    class Meta:
        model = ForwardZoneDelegation
        fields = "__all__"


class HinfoFilterSet(filters.FilterSet):
    class Meta:
        model = Hinfo
        fields = "__all__"


class HistoryFilterSet(filters.FilterSet):
    data = JSONFieldExactFilter(field_name="data")

    class Meta:
        model = History
        fields = "__all__"


class HostFilterSet(filters.FilterSet):
    class Meta:
        model = Host
        fields = "__all__"


class HostGroupFilterSet(filters.FilterSet):
    class Meta:
        model = HostGroup
        fields = "__all__"


class IpaddressFilterSet(filters.FilterSet):
    class Meta:
        model = Ipaddress
        fields = "__all__"


class LabelFilterSet(filters.FilterSet):
    class Meta:
        model = Label
        fields = "__all__"


class LocFilterSet(filters.FilterSet):
    class Meta:
        model = Loc
        fields = "__all__"


class MxFilterSet(filters.FilterSet):
    class Meta:
        model = Mx
        fields = "__all__"


class NameServerFilterSet(filters.FilterSet):
    class Meta:
        model = NameServer
        fields = "__all__"


class NaptrFilterSet(filters.FilterSet):
    class Meta:
        model = Naptr
        fields = "__all__"


class NetGroupRegexPermissionFilterSet(filters.FilterSet):
    range = CIDRFieldExactFilter(field_name="range")

    class Meta:
        model = NetGroupRegexPermission
        fields = "__all__"


class NetworkFilterSet(filters.FilterSet):
    network = CIDRFieldExactFilter(field_name="network")

    class Meta:
        model = Network
        fields = "__all__"


class NetworkExcludedRangeFilterSet(filters.FilterSet):
    class Meta:
        model = NetworkExcludedRange
        fields = "__all__"


class PtrOverrideFilterSet(filters.FilterSet):
    class Meta:
        model = PtrOverride
        fields = "__all__"


class ReverseZoneFilterSet(filters.FilterSet):
    network = CIDRFieldExactFilter(field_name="network")

    class Meta:
        model = ReverseZone
        fields = "__all__"


class ReverseZoneDelegationFilterSet(filters.FilterSet):
    class Meta:
        model = ReverseZoneDelegation
        fields = "__all__"

class SrvFilterSet(filters.FilterSet):
    class Meta:
        model = Srv
        fields = "__all__"


class SshfpFilterSet(filters.FilterSet):
    class Meta:
        model = Sshfp
        fields = "__all__"


class TxtFilterSet(filters.FilterSet):
    class Meta:
        model = Txt
        fields = "__all__"
