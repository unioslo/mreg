from django.test import TestCase
from rest_framework.request import Request, HttpRequest
from rest_framework.test import APIRequestFactory
from rest_framework import generics

from mreg.mixins import LowerCaseLookupMixin
from mreg.models.host import Host

from typing import cast

class HostDetailView(LowerCaseLookupMixin, generics.RetrieveAPIView):
    """Test view using the mixin with Host model."""
    queryset = Host.objects.all()
    lookup_field = 'name'


class ViewWithoutLookupField(LowerCaseLookupMixin, generics.RetrieveAPIView):
    """Test view without lookup_field defined."""
    queryset = Host.objects.all()
    # No lookup_field defined


class LowerCaseLookupMixinTestCase(TestCase):
    """Test suite for LowerCaseLookupMixin."""
    
    def setUp(self):
        """Set up test objects."""
        self.factory = APIRequestFactory()
        
        self.host1 = Host.objects.create(name="testhost.example.org", contact="test@example.org")
        self.host2 = Host.objects.create(name="anotherhost.example.org", contact="test@example.org")
    
    def test_get_object_lowercase_lookup(self):
        """Test that get_object performs case-insensitive lookup."""
        request = self.factory.get('/api/hosts/TESTHOST.EXAMPLE.ORG/')
        
        # Set up the view instance
        view_instance = HostDetailView()
        view_instance.kwargs = {'name': 'TESTHOST.EXAMPLE.ORG'}
        view_instance.request = cast(HttpRequest, request)
        view_instance.format_kwarg = None
        
        # Get the object - should find it despite uppercase
        obj = view_instance.get_object()
        self.assertEqual(obj, self.host1)
    
    def test_get_object_from_request_with_field(self):
        """Test get_object_from_request with explicit field parameter."""
        # Create request with data
        request = self.factory.post('/api/hosts/')
        drf_request = Request(request)
        drf_request._full_data = {'name': 'TESTHOST.EXAMPLE.ORG'}
        
        view = HostDetailView()
        view.request = cast(HttpRequest, drf_request)
        
        # Get object with explicit field
        obj = view.get_object_from_request(drf_request, field='name')
        self.assertEqual(obj, self.host1)
    
    def test_get_object_from_request_without_field(self):
        """Test get_object_from_request using lookup_field from view."""
        # Create request with data
        request = self.factory.post('/api/hosts/')
        drf_request = Request(request)
        drf_request._full_data = {'name': 'ANOTHERHOST.EXAMPLE.ORG'}
        
        view = HostDetailView()
        view.request = cast(HttpRequest, drf_request)
        
        # Get object without explicit field - should use lookup_field
        obj = view.get_object_from_request(drf_request)
        self.assertEqual(obj, self.host2)
    
    def test_get_object_from_request_no_field_no_lookup_field(self):
        """Test error when no field specified and view has no lookup_field."""
        request = self.factory.post('/api/hosts/')
        drf_request = Request(request)
        drf_request._full_data = {'name': 'test.example.org'}
        
        view = ViewWithoutLookupField()
        view.lookup_field = None  # type: ignore[assignment]  # Explicitly set to None to trigger the error
        view.request = cast(HttpRequest, drf_request)
        
        # The error should happen immediately when checking for lookup_field
        with self.assertRaises(AttributeError) as context:
            view.get_object_from_request(drf_request)
        self.assertIn("lookup_field defined", str(context.exception))
    
    def test_get_object_from_request_no_data(self):
        """Test get_object_from_request returns None when request has no data."""
        # Create request without data
        request = self.factory.post('/api/hosts/')
        drf_request = Request(request)
        # Don't set _full_data, so it will be None/empty
        
        view = HostDetailView()
        view.request = cast(HttpRequest, drf_request)
        
        obj = view.get_object_from_request(drf_request)
        self.assertIsNone(obj)
    
    def test_get_object_from_request_data_not_dict(self):
        """Test get_object_from_request returns None when data is not a dict."""
        # Create request with non-dict data (list)
        request = self.factory.post('/api/hosts/')
        drf_request = Request(request)
        drf_request._full_data = ['item1', 'item2']
        
        view = HostDetailView()
        view.request = cast(HttpRequest, drf_request)
        
        obj = view.get_object_from_request(drf_request)
        self.assertIsNone(obj)
    
    def test_get_object_from_request_field_not_in_data(self):
        """Test get_object_from_request returns None when field not in request data."""
        # Create request with data that doesn't have the lookup field
        request = self.factory.post('/api/hosts/')
        drf_request = Request(request)
        drf_request._full_data = {'other_field': 'value'}
        
        view = HostDetailView()
        view.request = cast(HttpRequest, drf_request)
        
        obj = view.get_object_from_request(drf_request)
        self.assertIsNone(obj)
    
    def test_get_object_from_request_not_found(self):
        """Test get_object_from_request returns None when object doesn't exist."""
        # Create request with non-existent host name
        request = self.factory.post('/api/hosts/')
        drf_request = Request(request)
        drf_request._full_data = {'name': 'nonexistent.example.org'}
        
        view = HostDetailView()
        view.request = cast(HttpRequest, drf_request)
        
        obj = view.get_object_from_request(drf_request)
        self.assertIsNone(obj)
