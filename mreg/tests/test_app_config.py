# mreg/tests/test_app_config.py
import os
from django.test import TestCase, override_settings

from mreg.apps import MregAppConfig
from mreg.models.network_policy import NetworkPolicyAttribute

# Create a test-specific subclass to provide a dummy path to make Django / AppConfig happy.
class DummyMregAppConfig(MregAppConfig):
    path = os.path.join(os.getcwd(), "mreg_test")

class MregAppConfigTests(TestCase):
    def setUp(self):
        # Instantiate and call ready() so our receiver is connected and exposed.
        self.app_config = DummyMregAppConfig("mreg", "mreg")
        self.app_config.ready()

    @override_settings(MREG_PROTECTED_POLICY_ATTRIBUTES="not a list")
    def test_invalid_protected_policy_attributes_type(self):
        with self.assertRaises(ValueError) as cm:
            self.app_config.create_protected_attributes(sender=self.app_config, app_config=self.app_config)
        self.assertIn("must be a list", str(cm.exception))

    @override_settings(MREG_PROTECTED_POLICY_ATTRIBUTES=["not a dict"])
    def test_invalid_protected_policy_attributes_not_dict(self):
        with self.assertRaises(ValueError) as cm:
            self.app_config.create_protected_attributes(sender=self.app_config, app_config=self.app_config)
        self.assertIn("must be a list of dictionaries", str(cm.exception))

    @override_settings(MREG_PROTECTED_POLICY_ATTRIBUTES=[{"description": "desc"}])
    def test_missing_name_key_in_protected_policy_attributes(self):
        with self.assertRaises(ValueError) as cm:
            self.app_config.create_protected_attributes(sender=self.app_config, app_config=self.app_config)
        self.assertIn("must contain a name key", str(cm.exception))

    @override_settings(MREG_PROTECTED_POLICY_ATTRIBUTES=[{"name": 123, "description": "desc"}])
    def test_invalid_name_type_in_protected_policy_attributes(self):
        with self.assertRaises(ValueError) as cm:
            self.app_config.create_protected_attributes(sender=self.app_config, app_config=self.app_config)
        self.assertIn("name must be a string", str(cm.exception))

    @override_settings(MREG_PROTECTED_POLICY_ATTRIBUTES=[{"name": "valid"}])
    def test_valid_protected_policy_attributes_no_description(self):
        self.app_config.create_protected_attributes(sender=self.app_config, app_config=self.app_config)
        attr = NetworkPolicyAttribute.objects.get(name="valid")
        self.assertEqual(attr.description, "Automatically created protected attribute.")

    @override_settings(MREG_PROTECTED_POLICY_ATTRIBUTES=[{"name": "valid", "description": 123}])
    def test_invalid_description_type_in_protected_policy_attributes(self):
        with self.assertRaises(ValueError) as cm:
            self.app_config.create_protected_attributes(sender=self.app_config, app_config=self.app_config)
        self.assertIn("description must be a string", str(cm.exception))

    @override_settings(MREG_CREATING_COMMUNITY_REQUIRES_POLICY_WITH_ATTRIBUTES="not a list")
    def test_invalid_creating_community_setting_type(self):
        with self.assertRaises(ValueError) as cm:
            self.app_config.create_protected_attributes(sender=self.app_config, app_config=self.app_config)
        self.assertIn("MREG_CREATING_COMMUNITY_REQUIRES_POLICY_WITH_ATTRIBUTES must be a list", str(cm.exception))

    @override_settings(MREG_CREATING_COMMUNITY_REQUIRES_POLICY_WITH_ATTRIBUTES=[123])
    def test_invalid_creating_community_setting_contents(self):
        with self.assertRaises(ValueError) as cm:
            self.app_config.create_protected_attributes(sender=self.app_config, app_config=self.app_config)
        self.assertIn("must be a list of strings", str(cm.exception))

    @override_settings(MREG_MAX_COMMUNITES_PER_NETWORK=-1)
    def test_invalid_max_communities(self):
        with self.assertRaises(ValueError) as cm:
            self.app_config.create_protected_attributes(sender=self.app_config, app_config=self.app_config)
        self.assertIn("MREG_MAX_COMMUNITES_PER_NETWORK must be an integer greater than or equal to 0", str(cm.exception))

    @override_settings(MREG_MAP_GLOBAL_COMMUNITY_NAMES="not a bool")
    def test_invalid_map_global_names(self):
        with self.assertRaises(ValueError) as cm:
            self.app_config.create_protected_attributes(sender=self.app_config, app_config=self.app_config)
        self.assertIn("MREG_MAP_GLOBAL_COMMUNITY_NAMES must be a boolean", str(cm.exception))

    @override_settings(MREG_GLOBAL_COMMUNITY_PREFIX=123)
    def test_invalid_global_prefix_type(self):
        with self.assertRaises(ValueError) as cm:
            self.app_config.create_protected_attributes(sender=self.app_config, app_config=self.app_config)
        self.assertIn("MREG_GLOBAL_COMMUNITY_PREFIX must be a string", str(cm.exception))

    @override_settings(MREG_GLOBAL_COMMUNITY_PREFIX="invalid*prefix")
    def test_invalid_global_prefix_regex(self):
        with self.assertRaises(ValueError) as cm:
            self.app_config.create_protected_attributes(sender=self.app_config, app_config=self.app_config)
        self.assertIn("must be a string containing only A-Za-z0-9-_", str(cm.exception))

    @override_settings(MREG_GLOBAL_COMMUNITY_PREFIX="a" * 61)
    def test_global_prefix_too_long(self):
        with self.assertRaises(ValueError) as cm:
            self.app_config.create_protected_attributes(sender=self.app_config, app_config=self.app_config)
        self.assertIn("has max length of", str(cm.exception))

    @override_settings(
        MREG_PROTECTED_POLICY_ATTRIBUTES=[{"name": "isolated", "description": "The network uses client isolation."}],
        MREG_CREATING_COMMUNITY_REQUIRES_POLICY_WITH_ATTRIBUTES=["some_attribute"],
        MREG_MAX_COMMUNITES_PER_NETWORK=20,
        MREG_MAP_GLOBAL_COMMUNITY_NAMES=True,
        MREG_GLOBAL_COMMUNITY_PREFIX="community"
    )
    def test_valid_settings_creates_protected_attribute(self):
        # Remove any preexisting instance.
        NetworkPolicyAttribute.objects.filter(name="isolated").delete()
        self.app_config.create_protected_attributes(sender=self.app_config, app_config=self.app_config)
        self.assertTrue(NetworkPolicyAttribute.objects.filter(name="isolated").exists())
