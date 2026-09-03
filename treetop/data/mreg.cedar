// MREG endpoint authorization. Each protected endpoint sends one request stack;
// TreeTop evaluates every leaf in one authorize call and MREG composes the result.

@id("MREG.authenticated_access")
permit (
    principal,
    action == MREG::Action::"authenticated_access",
    resource
);

@id("MREG.read_all")
permit (
    principal,
    action in
        [MREG::Action::"bacnet_id_read",
         MREG::Action::"cname_read",
         MREG::Action::"community_read",
         MREG::Action::"forward_zone_delegation_read",
         MREG::Action::"forward_zone_read",
         MREG::Action::"hinfo_read",
         MREG::Action::"host_community_mapping_read",
         MREG::Action::"host_contacts_read",
         MREG::Action::"host_group_read",
         MREG::Action::"host_policy_atom_read",
         MREG::Action::"host_policy_role_read",
         MREG::Action::"host_read",
         MREG::Action::"ipaddress_read",
         MREG::Action::"label_read",
         MREG::Action::"loc_read",
         MREG::Action::"mx_read",
         MREG::Action::"name_server_read",
         MREG::Action::"naptr_read",
         MREG::Action::"net_group_regex_permission_read",
         MREG::Action::"network_excluded_range_read",
         MREG::Action::"network_policy_attribute_read",
         MREG::Action::"network_policy_attribute_value_read",
         MREG::Action::"network_policy_read",
         MREG::Action::"network_read",
         MREG::Action::"ptr_override_read",
         MREG::Action::"reverse_zone_delegation_read",
         MREG::Action::"reverse_zone_read",
         MREG::Action::"srv_read",
         MREG::Action::"sshfp_read",
         MREG::Action::"txt_read"],
    resource
);

@id("MREG.user_info_self")
permit (
    principal,
    action == MREG::Action::"user_info_read",
    resource is MREG::Generic
)
when {
    resource has selfAccess && resource.selfAccess
};

@id("MREG.user_info_admin")
permit (
    principal in MREG::Group::"default-admin-group",
    action == MREG::Action::"user_info_read",
    resource is MREG::Generic
);

@id("MREG.user_info_hostgroup_admin")
permit (
    principal in MREG::Group::"default-groupadmin-group",
    action == MREG::Action::"user_info_read",
    resource is MREG::Generic
);

// Resources managed by the ordinary MREG administrator role.
@id("MREG.admin_crud")
permit (
    principal in MREG::Group::"default-admin-group",
    action in
        [MREG::Action::"host_create",
         MREG::Action::"host_update",
         MREG::Action::"host_delete",
         MREG::Action::"host_contacts_create",
         MREG::Action::"host_contacts_delete",
         MREG::Action::"ipaddress_create",
         MREG::Action::"ipaddress_update",
         MREG::Action::"ipaddress_delete",
         MREG::Action::"cname_create",
         MREG::Action::"cname_update",
         MREG::Action::"cname_delete",
         MREG::Action::"hinfo_create",
         MREG::Action::"hinfo_update",
         MREG::Action::"hinfo_delete",
         MREG::Action::"loc_create",
         MREG::Action::"loc_update",
         MREG::Action::"loc_delete",
         MREG::Action::"mx_create",
         MREG::Action::"mx_update",
         MREG::Action::"mx_delete",
         MREG::Action::"naptr_create",
         MREG::Action::"naptr_update",
         MREG::Action::"naptr_delete",
         MREG::Action::"name_server_create",
         MREG::Action::"name_server_update",
         MREG::Action::"name_server_delete",
         MREG::Action::"ptr_override_create",
         MREG::Action::"ptr_override_update",
         MREG::Action::"ptr_override_delete",
         MREG::Action::"sshfp_create",
         MREG::Action::"sshfp_update",
         MREG::Action::"sshfp_delete",
         MREG::Action::"srv_create",
         MREG::Action::"srv_update",
         MREG::Action::"srv_delete",
         MREG::Action::"txt_create",
         MREG::Action::"txt_update",
         MREG::Action::"txt_delete",
         MREG::Action::"bacnet_id_create",
         MREG::Action::"bacnet_id_update",
         MREG::Action::"bacnet_id_delete",
         MREG::Action::"community_create",
         MREG::Action::"community_update",
         MREG::Action::"community_delete",
         MREG::Action::"host_community_mapping_create",
         MREG::Action::"host_community_mapping_update",
         MREG::Action::"host_community_mapping_delete",
         MREG::Action::"label_create",
         MREG::Action::"label_update",
         MREG::Action::"label_delete",
         MREG::Action::"net_group_regex_permission_create",
         MREG::Action::"net_group_regex_permission_update",
         MREG::Action::"net_group_regex_permission_delete"],
    resource
);

@id("MREG.network_admin_crud")
permit (
    principal in MREG::Group::"default-networkadmin-group",
    action in
        [MREG::Action::"network_create",
         MREG::Action::"network_update",
         MREG::Action::"network_delete",
         MREG::Action::"network_excluded_range_create",
         MREG::Action::"network_excluded_range_update",
         MREG::Action::"network_excluded_range_delete",
         MREG::Action::"network_policy_create",
         MREG::Action::"network_policy_update",
         MREG::Action::"network_policy_delete",
         MREG::Action::"network_policy_attribute_create",
         MREG::Action::"network_policy_attribute_update",
         MREG::Action::"network_policy_attribute_delete",
         MREG::Action::"network_policy_attribute_value_create",
         MREG::Action::"network_policy_attribute_value_update",
         MREG::Action::"network_policy_attribute_value_delete",
         MREG::Action::"community_create",
         MREG::Action::"community_update",
         MREG::Action::"community_delete",
         MREG::Action::"host_create",
         MREG::Action::"host_delete"],
    resource
);

@id("MREG.hostgroup_admin_crud")
permit (
    principal in MREG::Group::"default-groupadmin-group",
    action in
        [MREG::Action::"host_group_create",
         MREG::Action::"host_group_update",
         MREG::Action::"host_group_delete",
         MREG::Action::"hostgroup_membership_update"],
    resource is MREG::HostGroup
);

@id("MREG.hostgroup_owner_update")
permit (
    principal,
    action == MREG::Action::"host_group_update",
    resource is MREG::HostGroup
)
when {
    resource has requesterIsOwner && resource.requesterIsOwner &&
    resource has descriptionUpdate && resource.descriptionUpdate
};

@id("MREG.hostgroup_owner_membership")
permit (
    principal,
    action == MREG::Action::"hostgroup_membership_update",
    resource is MREG::HostGroup
)
when {
    resource has requesterIsOwner && resource.requesterIsOwner &&
    resource has ownerMutation && !resource.ownerMutation
};

@id("MREG.hostpolicy_admin_crud")
permit (
    principal in MREG::Group::"default-hostpolicyadmin-group",
    action in
        [MREG::Action::"host_policy_atom_create",
         MREG::Action::"host_policy_atom_update",
         MREG::Action::"host_policy_atom_delete",
         MREG::Action::"host_policy_role_create",
         MREG::Action::"host_policy_role_update",
         MREG::Action::"host_policy_role_delete",
         MREG::Action::"hostpolicy_role_atom_membership_update",
         MREG::Action::"hostpolicy_role_host_membership_update"],
    resource
);

// These rules replace local post-policy denials in authoritative mode.
@id("MREG.invalid_or_unprivileged_dns_wildcard")
forbid (
    principal,
    action in
        [MREG::Action::"host_create",
         MREG::Action::"host_update",
         MREG::Action::"cname_create",
         MREG::Action::"cname_update",
         MREG::Action::"hinfo_create",
         MREG::Action::"hinfo_update",
         MREG::Action::"loc_create",
         MREG::Action::"loc_update",
         MREG::Action::"mx_create",
         MREG::Action::"mx_update",
         MREG::Action::"naptr_create",
         MREG::Action::"naptr_update",
         MREG::Action::"name_server_create",
         MREG::Action::"name_server_update",
         MREG::Action::"ptr_override_create",
         MREG::Action::"ptr_override_update",
         MREG::Action::"sshfp_create",
         MREG::Action::"sshfp_update",
         MREG::Action::"srv_create",
         MREG::Action::"srv_update",
         MREG::Action::"txt_create",
         MREG::Action::"txt_update"],
    resource
)
when {
    resource has nameLabels &&
    resource.nameLabels.contains("dns_wildcard") &&
    principal != MREG::User::"super" &&
    !(principal in MREG::Group::"default-super-group") &&
    (!resource.nameLabels.contains("dns_wildcard_valid_depth") ||
     !(principal in MREG::Group::"default-dns-wildcard-group"))
};

@id("MREG.unprivileged_dns_underscore")
forbid (
    principal,
    action in
        [MREG::Action::"host_create",
         MREG::Action::"host_update",
         MREG::Action::"cname_create",
         MREG::Action::"cname_update",
         MREG::Action::"hinfo_create",
         MREG::Action::"hinfo_update",
         MREG::Action::"loc_create",
         MREG::Action::"loc_update",
         MREG::Action::"mx_create",
         MREG::Action::"mx_update",
         MREG::Action::"naptr_create",
         MREG::Action::"naptr_update",
         MREG::Action::"name_server_create",
         MREG::Action::"name_server_update",
         MREG::Action::"ptr_override_create",
         MREG::Action::"ptr_override_update",
         MREG::Action::"sshfp_create",
         MREG::Action::"sshfp_update",
         MREG::Action::"txt_create",
         MREG::Action::"txt_update"],
    resource
)
when {
    resource has nameLabels &&
    resource.nameLabels.contains("dns_underscore") &&
    principal != MREG::User::"super" &&
    !(principal in MREG::Group::"default-super-group") &&
    !(principal in MREG::Group::"default-dns-underscore-group")
};

@id("MREG.unprivileged_restricted_ip")
forbid (
    principal,
    action in
        [MREG::Action::"host_create",
         MREG::Action::"host_update",
         MREG::Action::"ipaddress_create",
         MREG::Action::"ipaddress_update",
         MREG::Action::"ptr_override_create",
         MREG::Action::"ptr_override_update"],
    resource
)
when {
    resource has ip &&
    (resource.ip.isInRange(ip("10.0.0.0/32")) ||
     resource.ip.isInRange(ip("10.0.0.1/32")) ||
     resource.ip.isInRange(ip("10.0.0.2/32")) ||
     resource.ip.isInRange(ip("10.0.0.3/32")) ||
     resource.ip.isInRange(ip("10.0.0.255/32")) ||
     resource.ip.isInRange(ip("10.1.0.0/32")) ||
     resource.ip.isInRange(ip("10.1.0.1/32")) ||
     resource.ip.isInRange(ip("10.1.0.2/32")) ||
     resource.ip.isInRange(ip("10.1.0.3/32")) ||
     resource.ip.isInRange(ip("10.1.0.127/32")) ||
     resource.ip.isInRange(ip("192.168.1.0/32")) ||
     resource.ip.isInRange(ip("192.168.1.1/32")) ||
     resource.ip.isInRange(ip("192.168.1.2/32")) ||
     resource.ip.isInRange(ip("192.168.1.3/32")) ||
     resource.ip.isInRange(ip("192.168.1.255/32")) ||
     resource.ip.isInRange(ip("2001:db8::/128")) ||
     resource.ip.isInRange(ip("2001:db8::1/128")) ||
     resource.ip.isInRange(ip("2001:db8::2/128")) ||
     resource.ip.isInRange(ip("2001:db8::3/128"))) &&
    principal != MREG::User::"super" &&
    !(principal in MREG::Group::"default-super-group") &&
    !(principal in MREG::Group::"default-networkadmin-group")
};

// Explicit membership actions retained for custom/admin endpoints.
@id("MREG.admin_membership")
permit (
    principal in MREG::Group::"default-admin-group",
    action == MREG::Action::"admin_access",
    resource
);

@id("MREG.network_admin_membership")
permit (
    principal in MREG::Group::"default-networkadmin-group",
    action in
        [MREG::Action::"network_admin_access",
         MREG::Action::"ip_network_management",
         MREG::Action::"ip_reserved_management",
         MREG::Action::"ip_restricted_management",
         MREG::Action::"ip_gw_management",
         MREG::Action::"ip_broadcast_management"],
    resource
);

@id("MREG.hostgroup_admin_membership")
permit (
    principal in MREG::Group::"default-groupadmin-group",
    action == MREG::Action::"hostgroup_admin_access",
    resource
);

@id("MREG.hostpolicy_admin_membership")
permit (
    principal in MREG::Group::"default-hostpolicyadmin-group",
    action == MREG::Action::"hostpolicy_admin_access",
    resource
);

@id("MREG.dns_wildcard_admin_membership")
permit (
    principal in MREG::Group::"default-dns-wildcard-group",
    action == MREG::Action::"dns_wildcard_admin_access",
    resource
);

@id("MREG.dns_underscore_admin_membership")
permit (
    principal in MREG::Group::"default-dns-underscore-group",
    action == MREG::Action::"dns_underscore_admin_access",
    resource
);
