from rest_framework import (exceptions, status)


class ValidationError409(exceptions.APIException):
    status_code = status.HTTP_409_CONFLICT
