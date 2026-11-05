"""Authentication extensions for the generated OpenAPI document."""

from typing import TYPE_CHECKING

from drf_spectacular.extensions import OpenApiAuthenticationExtension

if TYPE_CHECKING:
    from drf_spectacular.openapi import AutoSchema


class KeycloakBearerScheme(OpenApiAuthenticationExtension):
    target_class = "mreg.authentication.KeycloakBearerAuthentication"
    name = "keycloakBearer"
    priority = 1

    def get_security_definition(self, auto_schema: AutoSchema) -> dict[str, str]:
        return {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
