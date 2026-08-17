from django.http import BadHeaderError
from django.test import SimpleTestCase

from rest_framework import serializers, status
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from mreg.api.responses import created_response, created_response_at_url


class CreatedObjectSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    name = serializers.CharField()


class CreatedResponseTest(SimpleTestCase):
    def setUp(self):
        self.serializer = CreatedObjectSerializer(
            instance={"id": 42, "name": "example"}
        )

    def test_created_response_builds_location_from_request_path(self):
        data = {"id": 42, "name": "example"}
        request = Request(APIRequestFactory().post("/api/v1/examples/"))

        response = created_response(request, self.serializer, 42)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data, data)
        self.assertEqual(response.headers["Location"], "/api/v1/examples/42")

    def test_created_response_encodes_lookup_value(self):
        request = Request(APIRequestFactory().post("/api/v1/examples/"))

        response = created_response(request, self.serializer, "unsafe/value\r\n")

        self.assertEqual(
            response.headers["Location"],
            "/api/v1/examples/unsafe%2Fvalue%0D%0A",
        )

    def test_created_response_preserves_safe_lookup_characters(self):
        request = Request(APIRequestFactory().post("/api/v1/networks/"))

        response = created_response(
            request,
            self.serializer,
            "2001:db8::/64",
            safe="/:",
        )

        self.assertEqual(
            response.headers["Location"],
            "/api/v1/networks/2001:db8::/64",
        )

    def test_created_response_at_url_uses_explicit_location(self):
        response = created_response_at_url(
            self.serializer,
            "https://example.test/api/v1/examples/42",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data, {"id": 42, "name": "example"})
        self.assertEqual(
            response.headers["Location"],
            "https://example.test/api/v1/examples/42",
        )

    def test_created_response_at_url_rejects_header_injection(self):
        with self.assertRaises(BadHeaderError):
            created_response_at_url(
                self.serializer,
                "/safe\r\nX-Injected: true",
            )
