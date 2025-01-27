from enum import Enum


class URL:
    class NetworkPolicy(str, Enum):
        LIST = "networkpolicy-list"
        DETAIL = "networkpolicy-detail"
        COMMUNITIES_LIST = "networkpolicy-communities-list"
        COMMUNITY_DETAIL = "networkpolicy-community-detail"
        COMMUNITY_HOSTS_LIST = "networkpolicy-community-hosts-list"
        COMMUNITY_HOST_DETAIL = "networkpolicy-community-host-detail"
        ATTRIBUTE_LIST = "networkpolicyattribute-list"
