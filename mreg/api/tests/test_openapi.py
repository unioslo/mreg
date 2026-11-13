from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from drf_spectacular.generators import SchemaGenerator
from rest_framework.views import APIView

from mreg.authentication import ExpiringTokenAuthentication, KeycloakBearerAuthentication


class OpenAPISchemaTest(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.schema = SchemaGenerator().get_schema(request=None, public=True)

    def test_public_endpoints_do_not_require_authentication(self):
        paths = self.schema["paths"]

        self.assertEqual(paths["/api/token-auth/"]["post"].get("security", []), [])
        self.assertEqual(paths["/api/meta/metrics"]["get"].get("security", []), [])

    def test_user_info_documents_username_query_parameter(self):
        operation = self.schema["paths"]["/api/meta/user"]["get"]
        username = next(
            parameter
            for parameter in operation.get("parameters", [])
            if parameter["name"] == "username"
        )

        self.assertEqual(username["in"], "query")
        self.assertFalse(username.get("required", False))
        self.assertEqual(username["schema"], {"type": "string"})

    def test_host_list_documents_ip_range_and_name_in_filters(self):
        operation = self.schema["paths"]["/api/v1/hosts/"]["get"]
        parameters = {parameter["name"]: parameter for parameter in operation["parameters"]}
        self.assertNotIn("network", parameters)
        self.assertEqual(parameters["ip_range"]["schema"], {"type": "string"})
        self.assertIn("no registered network is required", parameters["ip_range"]["description"])
        self.assertEqual(parameters["name__in"]["schema"]["type"], "array")
        self.assertEqual(parameters["name__in"]["schema"]["items"]["type"], "string")
        self.assertFalse(parameters["name__in"]["explode"])
        self.assertIn("page", parameters)
        self.assertIn("page_size", parameters)

    @override_settings(MREG_OIDC_ENABLED=True)
    def test_keycloak_and_local_tokens_are_documented_as_alternatives(self) -> None:
        with patch.object(APIView, "authentication_classes", (ExpiringTokenAuthentication, KeycloakBearerAuthentication)):
            schema = SchemaGenerator().get_schema(request=None, public=True)
        self.assertEqual(
            schema["components"]["securitySchemes"]["keycloakBearer"],
            {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
        )
        operation = schema["paths"]["/api/meta/user"]["get"]
        self.assertIn({"keycloakBearer": []}, operation["security"])
        self.assertIn({"tokenAuth": []}, operation["security"])
        logout = schema["paths"]["/api/token-logout/"]["post"]
        self.assertEqual(logout["security"], [{"tokenAuth": []}])
        self.assertEqual(schema["paths"]["/api/token-auth/"]["post"].get("security", []), [])

    def test_default_schema_has_no_keycloak_scheme(self) -> None:
        self.assertNotIn("keycloakBearer", self.schema["components"]["securitySchemes"])
