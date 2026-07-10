"""Tests for API view edge cases and error responses."""

from django.test import RequestFactory, SimpleTestCase
from rest_framework.exceptions import MethodNotAllowed, PermissionDenied
from rest_framework.test import APIRequestFactory

from mreg.api.v1.views import JSONContentTypeMixin, MregRetrieveUpdateDestroyAPIView
from mreg.api.v1.views_m2m import M2MPermissions
from mreg.models.host import Host, Ipaddress
from mreg.models.network import Network
from mreg.models.network_policy import Community, NetworkPolicy

from .tests import MregAPITestCase


class ContentTypeEnforcerTest(MregAPITestCase):
    """Test ContentTypeEnforcerMixin dispatch error handling."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.set_client_format_json()

    def test_post_with_wrong_content_type(self):
        """POST with a non-JSON content type is rejected."""
        response = self.client.post(
            "/api/v1/networkpolicies/",
            data='{"name": "test-policy"}',
            content_type="text/plain",  # Wrong content type
        )
        self.assertEqual(response.status_code, 415)  # Unsupported Media Type
        self.assertIn("unsupported_media_type", str(response.data))  # type: ignore[attr-defined]

    def test_patch_with_wrong_content_type(self):
        """PATCH with a non-JSON content type is rejected."""
        policy = NetworkPolicy.objects.create(name="test-policy")

        response = self.client.patch(
            f"/api/v1/networkpolicies/{policy.pk}",
            data='{"description": "test"}',
            content_type="application/xml",  # Wrong content type
        )
        self.assertEqual(response.status_code, 415)
        self.assertIn("unsupported_media_type", str(response.data))  # type: ignore[attr-defined]

    def test_delete_with_wrong_content_type(self):
        """DELETE with a body and non-JSON content type is rejected."""
        policy = NetworkPolicy.objects.create(name="test-policy")

        response = self.client.generic(
            "DELETE",
            f"/api/v1/networkpolicies/{policy.pk}",
            data=b"some body content",
            content_type="text/html",
        )
        self.assertEqual(response.status_code, 415)


class RequestBodyDetectionTest(SimpleTestCase):
    """Test _has_request_body edge cases."""

    def setUp(self):
        self.factory = RequestFactory()
        self.mixin = JSONContentTypeMixin()

    def test_chunked_transfer_encoding(self):
        request = self.factory.post("/", HTTP_TRANSFER_ENCODING="chunked")
        request.META.pop("CONTENT_LENGTH", None)

        self.assertTrue(self.mixin._has_request_body(request))

    def test_invalid_content_length_is_not_a_body(self):
        request = self.factory.post("/", HTTP_CONTENT_LENGTH="invalid")
        request.META["CONTENT_LENGTH"] = "invalid"

        self.assertFalse(self.mixin._has_request_body(request))

    def test_body_read_failure_is_not_a_body(self):
        class BrokenRequest:
            META = {}

            @property
            def body(self):
                raise OSError("broken request stream")

        self.assertFalse(self.mixin._has_request_body(BrokenRequest()))


class M2MPermissionsTests(SimpleTestCase):
    def test_permission_denied_when_check_fails(self):
        class DenyPermission:
            def has_m2m_change_permission(self, request, view):
                return False

        class DummyView(M2MPermissions):
            def __init__(self):
                self.request = RequestFactory().get("/")

            def get_permissions(self):
                return [DenyPermission()]

            def permission_denied(self, request):
                raise PermissionDenied()

        view = DummyView()

        with self.assertRaises(PermissionDenied):
            view.check_m2m_update_permission(view.request)


class MethodHandlingTests(SimpleTestCase):
    def test_put_method_not_allowed(self):
        request = APIRequestFactory().put("/")

        with self.assertRaises(MethodNotAllowed) as context:
            MregRetrieveUpdateDestroyAPIView().put(request)

        self.assertEqual(context.exception.status_code, 405)


class HostListPostTest(MregAPITestCase):
    """Test HostList.post error conditions."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.set_client_format_json()
        
        # Create a network for testing
        self.network = Network.objects.create(  # type: ignore[attr-defined]
            network="10.0.0.0/24",
            description="Test network",
        )

    def test_create_host_with_nonexistent_community(self):
        """Creating a host with a nonexistent community returns 404."""
        response = self.client.post(
            "/api/v1/hosts/",
            data={
                "name": "test.example.com",
                "network": str(self.network.network),
                "network_community": 99999,  # Non-existent community ID
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 404)
        self.assertIn("Community", str(response.data))  # type: ignore[attr-defined]
        self.assertIn("not found", str(response.data))  # type: ignore[attr-defined]

    def test_create_host_allocation_method_without_network(self):
        """An allocation method requires a network."""
        response = self.client.post(
            "/api/v1/hosts/",
            data={
                "name": "test.example.com",
                "ipaddress": "10.0.0.5",
                "allocation_method": "static",  # Not allowed without network
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("allocation_method", str(response.data))  # type: ignore[attr-defined]
        self.assertIn("network", str(response.data))  # type: ignore[attr-defined]


class HostContactsViewTests(MregAPITestCase):
    def setUp(self):
        super().setUp()
        self.set_client_format_json()
        self.host = Host.objects.create(name="contacts.example")

    def test_post_emails_not_list(self):
        response = self.client.post(
            f"/api/v1/hosts/{self.host.name}/contacts/",
            data={"emails": "not-a-list"},
            format="json",
        )
        self.assertEqual(response.status_code, 400)

    def test_delete_emails_not_list(self):
        response = self.client.delete(
            f"/api/v1/hosts/{self.host.name}/contacts/",
            data={"emails": "not-a-list"},
            format="json",
        )
        self.assertEqual(response.status_code, 400)


class HostDetailPatchTest(MregAPITestCase):
    """Test HostDetail.patch error conditions."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.set_client_format_json()
        
        # Create networks for testing
        self.network1 = Network.objects.create(  # type: ignore[attr-defined]
            network="10.0.0.0/24",
            description="Test network 1",
        )
        self.network2 = Network.objects.create(  # type: ignore[attr-defined]
            network="10.0.1.0/24",
            description="Test network 2",
        )

    def test_patch_host_ip_network_switch_with_community(self):
        """A community-bound IP cannot move to another network."""
        # Create a community (policy is created automatically)
        NetworkPolicy.objects.create(name="test-policy")  # type: ignore[attr-defined]
        community = Community.objects.create(  # type: ignore[attr-defined]
            name="test-community",
            description="Test community",
            network=self.network1,
        )
        
        # Create a host with IP in network1 and add to community
        host = Host.objects.create(name="test.example.com")  # type: ignore[attr-defined]
        ip = Ipaddress.objects.create(  # type: ignore[attr-defined]
            host=host,
            ipaddress="10.0.0.5",
            macaddress="aa:bb:cc:dd:ee:ff",  # MAC address required for community binding
        )
        # Add host to community using the add_to_community method with the IP
        host.add_to_community(community, ip)
        
        # Try to change IP to network2 (should fail due to community membership)
        response = self.client.patch(
            f"/api/v1/ipaddresses/{ip.pk}",
            data={"ipaddress": "10.0.1.5"},  # Different network
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 409)  # Conflict
        self.assertIn("community", str(response.data).lower())  # type: ignore[attr-defined]
        self.assertIn("network", str(response.data).lower())  # type: ignore[attr-defined]

    def test_patch_host_ip_same_network_with_community(self):
        """A community-bound IP can change within its current network."""
        NetworkPolicy.objects.create(name="test-policy")  # type: ignore[attr-defined]
        community = Community.objects.create(  # type: ignore[attr-defined]
            name="test-community",
            description="Test community",
            network=self.network1,
        )
        
        # Create a host with IP in network1 and add to community
        host = Host.objects.create(name="test.example.com")  # type: ignore[attr-defined]
        ip = Ipaddress.objects.create(  # type: ignore[attr-defined]
            host=host,
            ipaddress="10.0.0.5",
            macaddress="aa:bb:cc:dd:ee:ff",
        )
        host.add_to_community(community, ip)
        
        # Change IP to another IP in the SAME network (should succeed)
        response = self.client.patch(
            f"/api/v1/ipaddresses/{ip.pk}",
            data={"ipaddress": "10.0.0.10"},  # Same network1
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 204)


class NetworkDetailPatchTest(MregAPITestCase):
    """Test NetworkDetail.patch error conditions."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.set_client_format_json()
        
        # Create a network for testing
        self.network = Network.objects.create(  # type: ignore[attr-defined]
            network="10.0.0.0/24",
            description="Test network",
        )

    def test_patch_network_with_nonexistent_policy(self):
        """Assigning a nonexistent policy returns 404."""
        response = self.client.patch(
            f"/api/v1/networks/{self.network.network}",
            data={"policy": 99999},  # Non-existent policy ID
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 404)
        self.assertIn("policy", str(response.data).lower())  # type: ignore[attr-defined]
