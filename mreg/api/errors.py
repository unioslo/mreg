from enum import Enum

from rest_framework import (exceptions, status)


class ErrorCode(str, Enum):
    """Error code for DRF exceptions.

    Can be used for the top-level `code` attribute in DRF exceptions, as well
    as for the individual field-level errors in DRF ValidationError exceptions.
    """
    CONFLICT = "conflict"
    REQUIRED = "required"

    # DRF exception default codes
    INVALID = exceptions.ValidationError.default_code
    PARSE_ERROR = exceptions.ParseError.default_code
    AUTHENTICATION_FAILED = exceptions.AuthenticationFailed.default_code
    NOT_AUTHENTICATED = exceptions.NotAuthenticated.default_code
    PERMISSION_DENIED = exceptions.PermissionDenied.default_code
    NOT_FOUND = exceptions.NotFound.default_code
    METHOD_NOT_ALLOWED = exceptions.MethodNotAllowed.default_code
    UNSUPPORTED_MEDIA_TYPE = exceptions.UnsupportedMediaType.default_code
    THROTTLED = exceptions.Throttled.default_code

    def __str__(self):
        """Ensures that enum value is used as string representation.
        
        Python 3.11 changed the behavior of str mixin enums, so we must
        explictly define __str__ while we still support Python 3.10, 
        and thus cannot use `StrEnum`.
        """
        return self.value


class Conflict(exceptions.APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "The request conflicts with the current state of the resource."
    default_code = ErrorCode.CONFLICT
