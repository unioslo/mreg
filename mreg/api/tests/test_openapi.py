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
