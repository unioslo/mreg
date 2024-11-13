from rest_framework import (exceptions, status)

from typing import Any

class CustomAPIExceptionError(exceptions.APIException):
    def __init__(self, detail: Any = None):
        detail = {"ERROR": detail if detail is not None else self.default_detail}
        super().__init__(detail)


class ValidationError400(CustomAPIExceptionError):
    status_code = 400
    default_detail:str = 'Bad Request'

class ValidationError403(CustomAPIExceptionError):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail:str = 'Forbidden'

class ValidationError404(CustomAPIExceptionError):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail:str = 'Not Found'

class ValidationError409(CustomAPIExceptionError):
    status_code = status.HTTP_409_CONFLICT
    default_detail:str = 'Conflict'

class InternalServerError500(CustomAPIExceptionError):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail:str = 'Internal Server Error'

class NoIpAddressesError404(ValidationError404):
    default_detail:str = 'No free ip addresses found in the network.'