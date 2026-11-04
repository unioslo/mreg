"""Authentication extensions for the generated OpenAPI document."""

from drf_spectacular.extensions import OpenApiAuthenticationExtension


class KeycloakBearerScheme(OpenApiAuthenticationExtension):
    target_class = "mreg.authentication.KeycloakBearerAuthentication"
    name = "keycloakBearer"
    priority = 1

    def get_security_definition(self, auto_schema):
        return {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
