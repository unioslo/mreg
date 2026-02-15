
# Policy Actions

This section documents the policy actions currently used by MREG permission checks.

Related documentation:

- Parity test workflow and triage: [`parity_testing.md`](./parity_testing.md)

## Source of Truth

- Policy definitions: `treetop/data/mreg.cedar`
- Action generation in code: `mreg/api/permissions.py` (`ParityMixin._crud_action`)
- Parity transport/logging: `mreg/api/treetop.py`

## Adding a New Protected Resource

When introducing a new resource that should be parity-checked, use this checklist:

1. Ensure the permission path reaches `ParityMixin.pp()` or `pp_generic_action()`.
2. Confirm CRUD action dispatch is used (`<resource>_<create|read|update|delete>`).
3. Verify resource kind resolution works for the endpoint:
   - Prefer serializer `Meta.model`.
   - Fallbacks should remain stable for non-model views.
4. Verify resource ID resolution produces stable IDs for list/detail/custom views.
5. Add or update Cedar actions/rules in `treetop/data/mreg.cedar`.
6. If policy conditions depend on derived labels, update `treetop/data/labels.json`.
7. Add tests for create/read/update/delete behavior and group/admin overrides.
8. Run parity checks and confirm zero mismatches.
9. If tests mutate permissions mid-test, scope `disable_policy_parity()` as narrowly as possible.

## Resource Kind and ID Resolution

`ParityMixin` resolves resource kind and ID using deterministic fallbacks.

Resource kind fallback order (`_resource_kind_from_view`):

1. `obj.__class__.__name__` when object is available
2. `validated_serializer.Meta.model.__name__`
3. `view.get_serializer_class().Meta.model.__name__`
4. `validated_serializer.instance.__class__.__name__`
5. View class name with suffixes (`List`, `Detail`, `View`) stripped

Resource ID fallback order (`_resource_id_from_view`):

1. Object attributes: `pk`, `id`, `name`
2. Request/serializer data keys: `pk`, `id`, `name`
3. `validated_serializer.instance` attributes: `pk`, `id`, `name`
4. URL kwargs: `pk`, `id`, `name`, `cpk`, `hostpk`, `network`
5. Default `"any"`

## CRUD Action Naming

For model-backed checks, action names are generated as:

`<resource_kind_snake_case>_<operation>`

Where operation is mapped from HTTP method:

- `GET`, `HEAD`, `OPTIONS` -> `read`
- `POST` -> `create`
- `PUT`, `PATCH` -> `update`
- `DELETE` -> `delete`

## CRUD Actions Declared in Cedar

- `host_create`, `host_read`, `host_update`, `host_delete`
- `host_contacts_read`
- `ipaddress_create`, `ipaddress_read`, `ipaddress_update`, `ipaddress_delete`
- `cname_create`, `cname_read`, `cname_update`, `cname_delete`
- `hinfo_create`, `hinfo_read`, `hinfo_update`, `hinfo_delete`
- `loc_create`, `loc_read`, `loc_update`, `loc_delete`
- `mx_create`, `mx_read`, `mx_update`, `mx_delete`
- `naptr_create`, `naptr_read`, `naptr_update`, `naptr_delete`
- `name_server_create`, `name_server_read`, `name_server_update`, `name_server_delete`
- `ptr_override_create`, `ptr_override_read`, `ptr_override_update`, `ptr_override_delete`
- `sshfp_create`, `sshfp_read`, `sshfp_update`, `sshfp_delete`
- `srv_create`, `srv_read`, `srv_update`, `srv_delete`
- `txt_create`, `txt_read`, `txt_update`, `txt_delete`
- `bacnet_id_create`, `bacnet_id_read`, `bacnet_id_update`, `bacnet_id_delete`
- `community_create`, `community_read`, `community_update`, `community_delete`

## Non-CRUD Actions Declared in Cedar

- `admin_access`
- `network_admin_access`
- `hostgroup_admin_access`
- `hostpolicy_admin_access`
- `dns_wildcard_admin_access`
- `dns_underscore_admin_access`
- `ip_gw_management`
- `ip_broadcast_management`
- `ip_network_management`
- `ip_reserved_management`
- `ip_restricted_management`
- `create_label`
- `delete_label`
- `view_label`
- `edit_label`

## Attribute Contract for Policy Checks

All resource attributes are normalized through `ParityMixin._normalize_resource_attrs`:

- `kind` is always added using snake_case resource kind.
- Attribute values are stringified.
- In `policy_parity`, string values that parse as IPs are sent as IP-typed attributes, otherwise as string attributes.

Common attribute payloads in current checks:

| Context | Typical action(s) | Attributes sent |
| --- | --- | --- |
| Safe/read precheck in `IsGrantedNetGroupRegexPermission.has_permission` | `<resource>_read` | `kind`, `path` |
| Host/IP netgroup evaluation (`has_perm`) | CRUD action from method | `kind`, `hostname`, optional `ip` |
| Create admin parity check | `<resource>_create` | `kind` + flattened serializer data |
| Update admin parity check | `<resource>_update` | `kind` + stringified validated data |
| Destroy admin parity check | `<resource>_delete` | `kind`, `id` |

## Wildcard Action Rules

These rules do not enumerate action names and therefore match any action:

- `MREG.superadmin`: principal in `default-super-group` may perform any action.
- `global.super_admin_allow_all_policy`: principal `User::"super"` may perform any action.

## Code-Emitted Parity Actions

The code also emits parity checks for:

- `superuser_access`
- `is_superuser`

These are covered by wildcard superadmin rules in Cedar.
