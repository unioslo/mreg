import re

from django.apps import AppConfig
from django.conf import settings
from django.db.models.signals import post_migrate

GLOBAL_PREFIX_REGEX = r'^[A-Za-z0-9-_]+$'
MAX_GLOBAL_PREFIX_LENGTH = 60

class MregAppConfig(AppConfig):
    name = 'mreg'

    def ready(self):
        import mreg.signals # noqa
        from mreg.models.network_policy import NetworkPolicyAttribute

        def _validate_mreg_prefixed_settings():
            protected_attrs = getattr(settings, 'MREG_PROTECTED_POLICY_ATTRIBUTES', [])
            if not isinstance(protected_attrs, list):  
                raise ValueError('Config option MREG_PROTECTED_POLICY_ATTRIBUTES must be a list.') 

            for attr in protected_attrs:
                if not isinstance(attr, dict):  
                    raise ValueError('Config option MREG_PROTECTED_POLICY_ATTRIBUTES must be a list of dictionaries.')
                
                if 'name' not in attr:
                    raise ValueError('Config option MREG_PROTECTED_POLICY_ATTRIBUTES must contain a name key.')
                
                if not isinstance(attr['name'], str):
                    raise ValueError('Config option MREG_PROTECTED_POLICY_ATTRIBUTES name must be a string.')
                
                if 'description' in attr and not isinstance(attr['description'], str):
                    raise ValueError('Config option MREG_PROTECTED_POLICY_ATTRIBUTES description must be a string.')

            creating_community = getattr(settings, 'MREG_CREATING_COMMUNITY_REQUIRES_POLICY_WITH_ATTRIBUTES', [])
            if not isinstance(creating_community, list):
                raise ValueError('Config option MREG_CREATING_COMMUNITY_REQUIRES_POLICY_WITH_ATTRIBUTES must be a list.')
            
            for attr in creating_community:
                if not isinstance(attr, str):
                    raise ValueError('Config option MREG_CREATING_COMMUNITY_REQUIRES_POLICY_WITH_ATTRIBUTES must be a list of strings.')

            max_communities = getattr(settings, 'MREG_MAX_COMMUNITES_PER_NETWORK', 20)
            if not isinstance(max_communities, int) or max_communities < 0:
                raise ValueError('Config option MREG_MAX_COMMUNITES_PER_NETWORK must be an integer greater than or equal to 0.')
            
            map_global_names = getattr(settings, 'MREG_MAP_GLOBAL_COMMUNITY_NAMES', False)
            if not isinstance(map_global_names, bool):
                raise ValueError('Config option MREG_MAP_GLOBAL_COMMUNITY_NAMES must be a boolean.')
            
            global_prefix = getattr(settings, 'MREG_GLOBAL_COMMUNITY_TEMPLATE_PATTERN', 'community')
            if not isinstance(global_prefix, str):
                raise ValueError('Config option MREG_GLOBAL_COMMUNITY_TEMPLATE_PATTERN must be a string.')

            # Global prefix must be form A-Za-z0-9-_, so we'll regexp-match this.
            if not re.match(GLOBAL_PREFIX_REGEX, global_prefix):
                raise ValueError('Config option MREG_GLOBAL_COMMUNITY_TEMPLATE_PATTERN must be a string containing only A-Za-z0-9-_.')
            
            # Max length of the global prefix is 64 characters, but we set aside 4 characters for the index.
            if len(global_prefix) > MAX_GLOBAL_PREFIX_LENGTH:
                raise ValueError(f'Config option MREG_GLOBAL_COMMUNITY_TEMPLATE_PATTERN has max length of {MAX_GLOBAL_PREFIX_LENGTH}.')


        def create_protected_attributes(sender, **kwargs):
            _validate_mreg_prefixed_settings()
            protected_attrs = getattr(settings, 'MREG_PROTECTED_POLICY_ATTRIBUTES', [])

            for attr in protected_attrs:
                name = attr.get("name")
                description = attr.get("description", "Automatically created protected attribute.")

                if name:
                    NetworkPolicyAttribute.objects.get_or_create(
                        name=name,
                        defaults={'description': description}
                    )

        # Expose the receiver for testing
        self.create_protected_attributes = create_protected_attributes
        # Connect the receiver to the post_migrate signal.
        post_migrate.connect(create_protected_attributes, sender=self)
