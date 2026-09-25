from django.contrib.auth.models import AnonymousUser
from django.test import TestCase, RequestFactory
from rest_framework.exceptions import NotAuthenticated

from mreg.models.auth import User


class UserFromRequestTests(TestCase):
    def test_from_request_unauthenticated_raises(self):
        factory = RequestFactory()
        request = factory.get("/api/v1/hosts/")
        request.user = AnonymousUser()

        with self.assertRaises(NotAuthenticated):
            User.from_request(request)
