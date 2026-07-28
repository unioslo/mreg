from django.test import SimpleTestCase

from drf_spectacular.generators import SchemaGenerator


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
