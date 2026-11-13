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

    def test_snapshot_documents_download_formats_and_options(self):
        operation = self.schema["paths"]["/api/v1/snapshot"]["get"]
        response = operation["responses"]["200"]
        self.assertEqual(set(response["content"]), {"application/vnd.uio.mreg-snapshot+tar", "application/json"})
        for representation in response["content"].values():
            self.assertEqual(representation["schema"], {"type": "string", "format": "binary"})
        self.assertEqual(response["headers"]["Content-Encoding"]["schema"]["enum"], ["gzip"])
        self.assertIn("Content-Digest", response["headers"])
        parameters = {parameter["name"]: parameter for parameter in operation["parameters"]}
        self.assertEqual(parameters["format"]["schema"]["enum"], ["mreg-import-json-v1", "mreg-snapshot-v1"])
        self.assertEqual(parameters["include_permissions"]["schema"]["enum"], ["false", "true"])
        self.assertEqual(parameters["validate"]["schema"]["enum"], ["true"])
        self.assertEqual(parameters["include_audit"]["schema"]["enum"], ["false"])
        self.assertEqual(parameters["redact"]["schema"]["enum"], ["false"])
        self.assertTrue(operation["security"])
