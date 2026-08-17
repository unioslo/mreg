from django.http import BadHeaderError
from django.test import SimpleTestCase

from rest_framework import status

from mreg.api.responses import created_response


class CreatedResponseTest(SimpleTestCase):
    def test_created_response_has_consistent_shape(self):
        data = {"id": 42, "name": "example"}

        response = created_response(data, location="/api/v1/examples/42")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data, data)
        self.assertEqual(response.headers["Location"], "/api/v1/examples/42")

    def test_created_response_rejects_header_injection(self):
        with self.assertRaises(BadHeaderError):
            created_response(data={}, location="/safe\r\nX-Injected: true")
