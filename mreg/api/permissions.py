from django.conf import settings
from rest_framework.permissions import BasePermission

class IsInRequiredGroup(BasePermission):
    """
    Allows only access to users in the required group.
    """

    def has_permission(self, request, view):
        if not bool(request.user and request.user.is_authenticated):
            return False
        REQUIRED_USER_GROUP = getattr(settings, 'REQUIRED_USER_GROUP', None)
        if REQUIRED_USER_GROUP is None:
            return True
        return request.user.groups.filter(name=REQUIRED_USER_GROUP).exists()
