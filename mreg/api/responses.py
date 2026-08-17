from typing import Any

from rest_framework import status
from rest_framework.response import Response


def created_response(data: Any, *, location: str) -> Response:
    """Return a successful create response with its resource location."""
    return Response(
        data,
        status=status.HTTP_201_CREATED,
        headers={"Location": location},
    )


def error_body(message: str) -> dict[str, str]:
    return {"error": message}


def error_response(message: str, status: int) -> Response:
    return Response(error_body(message), status=status)
