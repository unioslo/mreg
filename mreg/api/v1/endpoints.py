from enum import Enum


class URL:
    """URL names for the API endpoints.
    
    These are used to generate URLs in the API and to refer to them in the code. The names
    themselves are hooked into the URLs in the declaration of the URLs in urls.py.
    """
    class NetworkPolicy(str, Enum):
        """Network Policy-related endpoints."""

        LIST = "networkpolicy-list"
        DETAIL = "networkpolicy-detail"
        COMMUNITIES_LIST = "networkpolicy-communities-list"
        COMMUNITY_DETAIL = "networkpolicy-community-detail"
        COMMUNITY_HOSTS_LIST = "networkpolicy-community-hosts-list"
        COMMUNITY_HOST_DETAIL = "networkpolicy-community-host-detail"
        ATTRIBUTE_LIST = "networkpolicyattribute-list"
        ATTRIBUTE_DETAIL = "networkpolicyattribute-detail"        
