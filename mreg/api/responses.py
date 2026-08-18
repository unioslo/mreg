from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import BaseSerializer

from mreg.api.v1.location import location_for


def created_response_at_url(serializer: BaseSerializer, url: str) -> Response:
    """Return a 201 response with serialized data and an explicit Location URL."""
    return Response(
        serializer.data,
        status=status.HTTP_201_CREATED,
        headers={"Location": url},
    )


def created_response(
    request: Request,
    serializer: BaseSerializer,
    lookup_value: object,
    *,
    safe: str = "",
) -> Response:
    """Return a 201 response whose Location extends the request collection path."""
    return created_response_at_url(
        serializer,
        location_for(request.path, lookup_value, safe=safe),
    )


def error_body(message: str) -> dict[str, str]:
    return {"error": message}


def error_response(message: str, status: int) -> Response:
    return Response(error_body(message), status=status)
