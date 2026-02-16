"""Example tests demonstrating how to disable parity checking for permission-modifying tests.

This file serves as documentation and can be used as a template.

Note: This file contains example code and is not meant to be run as actual tests.
Type checking is disabled for simplicity.
"""
# type: ignore

from django.contrib.auth.models import Group

from mreg.api.v1.tests.tests import MregAPITestCase
from mreg.api.treetop import disable_policy_parity
from mreg.api.test_utils import PermissionModifyingTestCase
from mreg.models.network import NetGroupRegexPermission


class ExamplePermissionTestWithContextManager(MregAPITestCase):
    """Example: Using context manager to disable parity checking for specific test sections."""
    
    def test_user_gains_permission_mid_test(self):
        """Test that a user gains access when added to a group.
        
        This test modifies permissions mid-test, so we disable parity checking
        during the modification and subsequent API calls.
        """
        # Create a group and permission
        group = Group.objects.create(name='example_group')
        NetGroupRegexPermission.objects.create(
            group='example_group',
            range='10.0.0.0/24',
            regex=r'.*\.example\.org$'
        )
        
        # Get a non-privileged user client
        client = self.get_token_client(superuser=False, adminuser=False)
        
        # First, verify user cannot create host (should fail)
        # This is still subject to parity checking (no modifications yet)
        response = client.post('/api/v1/hosts/', {
            'name': 'test.example.org',
            'ipaddress': '10.0.0.1'
        })
        self.assertEqual(response.status_code, 403)
        
        # Now we're going to modify permissions, so disable parity checking
        with disable_policy_parity():
            # Add user to the permission group
            self.user.groups.add(group)
            
            # Now the user should have permission
            # (parity checking is disabled because legacy and policy are out of sync)
            response = client.post('/api/v1/hosts/', {
                'name': 'test2.example.org',
                'ipaddress': '10.0.0.2'
            })
            self.assertEqual(response.status_code, 201)
            
            # Clean up
            host_url = response['Location']
            client.delete(host_url)
        
        # Parity checking resumes after the context exits
        # (though we typically don't make more permission-sensitive calls after this)


class ExamplePermissionTestWithMixin(PermissionModifyingTestCase, MregAPITestCase):
    """Example: Using mixin to disable parity checking for entire test class.
    
    Use this approach when ALL tests in a class modify permissions.
    """
    
    def test_add_user_to_group(self):
        """All tests in this class have parity checking disabled automatically."""
        group = Group.objects.create(name='test_group')
        
        # Parity checking is already disabled by the mixin
        self.user.groups.add(group)
        
        # Make API calls without worrying about parity
        response = self.client.get('/api/v1/hosts/')
        self.assertEqual(response.status_code, 200)
    
    def test_remove_user_from_group(self):
        """Another test - still no parity checking."""
        group = Group.objects.create(name='test_group')
        self.user.groups.add(group)
        
        # Remove from group
        self.user.groups.remove(group)
        
        # Make API calls
        response = self.client.get('/api/v1/hosts/')
        self.assertEqual(response.status_code, 200)


class ExampleComplexPermissionTest(MregAPITestCase):
    """Example: Complex test with multiple permission changes."""
    
    def test_permission_escalation_and_deescalation(self):
        """Test user gaining and losing permissions multiple times.
        
        This shows how to use multiple context managers in sequence.
        """
        # Create multiple groups with different permissions
        group1 = Group.objects.create(name='group1')
        group2 = Group.objects.create(name='group2')
        
        NetGroupRegexPermission.objects.create(
            group='group1',
            range='10.0.0.0/24',
            regex=r'.*\.example\.org$'
        )
        NetGroupRegexPermission.objects.create(
            group='group2',
            range='10.0.1.0/24',
            regex=r'.*\.example\.com$'
        )
        
        client = self.get_token_client(superuser=False, adminuser=False)
        
        # User starts with no permissions
        response = client.post('/api/v1/hosts/', {
            'name': 'test.example.org',
            'ipaddress': '10.0.0.1'
        })
        self.assertEqual(response.status_code, 403)
        
        # Gain permission to .org domain
        with disable_policy_parity():
            self.user.groups.add(group1)
            
            response = client.post('/api/v1/hosts/', {
                'name': 'test.example.org',
                'ipaddress': '10.0.0.2'
            })
            self.assertEqual(response.status_code, 201)
            client.delete(response['Location'])
        
        # Switch to different permission group
        with disable_policy_parity():
            self.user.groups.remove(group1)
            self.user.groups.add(group2)
            
            # Should now have access to .com but not .org
            response = client.post('/api/v1/hosts/', {
                'name': 'test.example.com',
                'ipaddress': '10.0.1.1'
            })
            self.assertEqual(response.status_code, 201)
            client.delete(response['Location'])
            
            response = client.post('/api/v1/hosts/', {
                'name': 'test.example.org',
                'ipaddress': '10.0.0.3'
            })
            self.assertEqual(response.status_code, 403)


# Note: You can also use pytest markers for documentation purposes:
# 
# import pytest
# 
# @pytest.mark.modifies_permissions
# class TestWithMarker(MregAPITestCase):
#     """Tests marked for documentation that they modify permissions."""
#     
#     def test_something(self):
#         with disable_policy_parity():
#             # modify permissions
#             pass
