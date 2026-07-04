from rest_framework.response import Response


def error_body(message: str) -> dict[str, str]:
    return {"error": message}


def error_response(message: str, status: int) -> Response:
    return Response(error_body(message), status=status)
