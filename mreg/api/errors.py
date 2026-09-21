from enum import StrEnum

from rest_framework import (exceptions, status)


class ErrorCode(StrEnum):
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


class Conflict(exceptions.APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "The request conflicts with the current state of the resource."
    default_code = ErrorCode.CONFLICT
