// MREG permissions example.

// Common CRUD action sets for resource-managed APIs.
// Keep this list in sync with mreg/api/permissions.py::_crud_action.

@id("MREG.read_all")
permit (
    principal,
    action in
        [MREG::Action::"host_read",
         MREG::Action::"host_contacts_read",
         MREG::Action::"ipaddress_read",
         MREG::Action::"cname_read",
         MREG::Action::"hinfo_read",
         MREG::Action::"loc_read",
         MREG::Action::"mx_read",
         MREG::Action::"naptr_read",
         MREG::Action::"name_server_read",
         MREG::Action::"ptr_override_read",
         MREG::Action::"sshfp_read",
         MREG::Action::"srv_read",
         MREG::Action::"txt_read",
         MREG::Action::"bacnet_id_read",
         MREG::Action::"community_read"],
    resource
);

@id("MREG.admin_crud")
permit (
    principal in MREG::Group::"default-admin-group",
    action in
        [MREG::Action::"host_create",
         MREG::Action::"host_update",
         MREG::Action::"host_delete",
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
         MREG::Action::"community_delete"],
    resource
);

@id("MREG.admins_policy")
permit (
    principal in MREG::Group::"admins",
    action in
        [MREG::Action::"host_create",
         MREG::Action::"host_read",
         MREG::Action::"host_update",
         MREG::Action::"host_delete"],
    resource is Host
);

// Webadmins can edit, delete, or create hosts with a name label containing "webserver", and the IP
// address must be in the range 192.168.1.0/24
@id("MREG.webadmins_policy")
permit (
    principal in MREG::Group::"webadmins",
    action in
        [MREG::Action::"host_create",
         MREG::Action::"host_read",
         MREG::Action::"host_update",
         MREG::Action::"host_delete"],
    resource is Host
)
when
{
    resource.nameLabels.contains("webserver") &&
    resource.ip.isInRange(ip("192.168.1.0/24"))
};

// Admins can manipulate any IP address, even if it is a gw, a broadcast address,
// the network address, reserved. These three groups are unified as "restricted" IPs.
@id("MREG.admins_ip_policy")
permit (
    principal in MREG::Group::"admins",
    action in
        [MREG::Action::"ip_gw_management",
         MREG::Action::"ip_broadcast_management",
         MREG::Action::"ip_network_management",
         MREG::Action::"ip_reserved_management",
         MREG::Action::"ip_restricted_management"],
    resource is IPAddress
);


/// Test group access, used during testing.
@id("MREG.test_group_policy")
permit (
    principal in MREG::Group::"testgroup",
    action in
        [MREG::Action::"host_create",
         MREG::Action::"host_update",
         MREG::Action::"host_delete",
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
         MREG::Action::"community_delete"],
    resource
) when {
    resource has hostname &&
    (
        (
            action in
                [MREG::Action::"cname_create",
                 MREG::Action::"cname_update",
                 MREG::Action::"cname_delete"] &&
            !(resource has ip) &&
            resource.hostname like "ho*.example.org"
        ) ||
        (
            !(action in
                [MREG::Action::"cname_create",
                 MREG::Action::"cname_update",
                 MREG::Action::"cname_delete"]) &&
            resource.hostname like "*.example.org" &&
            resource has ip &&
            (
                resource.ip.isInRange(ip("10.0.0.0/24")) ||
                resource.ip.isInRange(ip("10.1.0.0/25")) ||
                resource.ip.isInRange(ip("192.168.1.0/24")) ||
                resource.ip.isInRange(ip("192.168.2.1/32")) ||
                resource.ip.isInRange(ip("2001:db8::/64")) ||
                resource.ip.isInRange(ip("2001:db8::1/128")) ||
                resource.ip.isInRange(ip("2002:db9::/64"))
            )
        )
    )
};

/// Network admin permissions used in tests where network-admin users also
/// receive NetGroupRegexPermission entries.
@id("MREG.network_admin_group_policy")
permit (
    principal in MREG::Group::"default-networkadmin-group",
    action in
        [MREG::Action::"host_create",
         MREG::Action::"host_update",
         MREG::Action::"host_delete",
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
         MREG::Action::"community_delete"],
    resource
) when {
    resource has hostname &&
    (
        (
            action in
                [MREG::Action::"cname_create",
                 MREG::Action::"cname_update",
                 MREG::Action::"cname_delete"] &&
            !(resource has ip) &&
            resource.hostname like "ho*.example.org"
        ) ||
        (
            !(action in
                [MREG::Action::"cname_create",
                 MREG::Action::"cname_update",
                 MREG::Action::"cname_delete"]) &&
            resource.hostname like "*.example.org" &&
            resource has ip &&
            (
                resource.ip.isInRange(ip("10.0.0.0/24")) ||
                resource.ip.isInRange(ip("10.1.0.0/25")) ||
                resource.ip.isInRange(ip("192.168.1.0/24")) ||
                resource.ip.isInRange(ip("192.168.2.1/32")) ||
                resource.ip.isInRange(ip("2001:db8::/64")) ||
                resource.ip.isInRange(ip("2001:db8::1/128")) ||
                resource.ip.isInRange(ip("2002:db9::/64"))
            )
        )
    )
};

/// Network Admins can manage any IP in any network
@id("MREG.network_admins_ip_network_policy")
permit (
    principal in MREG::Group::"default-networkadmin-group",
    action == MREG::Action::"ip_network_management",
    resource is IPAddress
);

/// Users can only manage IPs in specific networks
@id("MREG.users_ip_network_policy")
permit (
    principal in MREG::Group::"users",
    action == MREG::Action::"ip_network_management",
    resource is IPAddress
)
when
{
    resource.ip.isInRange(ip("192.168.1.0/24")) ||
    resource.ip.isInRange(ip("10.0.0.0/8"))
};

/// Admins can do whatever with labels.
@id("MREG.labels_admin_policy")
permit (
    principal in MREG::Group::"default-super-group",
    action in
        [MREG::Action::"create_label",
         MREG::Action::"delete_label",
         MREG::Action::"view_label",
         MREG::Action::"edit_label"],
    resource is Label
);

/// Superadmins
@id("MREG.superadmin")
permit (
    principal in MREG::Group::"default-super-group",
    action, // Superadmins don't care what the action is
    resource
);

/// Normal admins
@id("MREG.admin")
permit (
    principal in MREG::Group::"default-admin-group",
    action == MREG::Action::"admin_access",
    resource
);

/// Network admins (group-membership permission check)
@id("MREG.network_admin")
permit (
    principal in MREG::Group::"default-networkadmin-group",
    action == MREG::Action::"network_admin_access",
    resource
);

/// Host group admins (group-membership permission check)
@id("MREG.hostgroup_admin")
permit (
    principal in MREG::Group::"default-groupadmin-group",
    action == MREG::Action::"hostgroup_admin_access",
    resource
);

/// Host Policy Admins
@id("MREG.hostpolicy_admin")
permit (
    principal in MREG::Group::"default-hostpolicyadmin-group",
    action == MREG::Action::"hostpolicy_admin_access",
    resource
);

/// DNS Wildcard Admins
@id("MREG.dns_wildcard_admin")
permit (
    principal in MREG::Group::"default-dns-wildcard-group",
    action == MREG::Action::"dns_wildcard_admin_access",
    resource
);

/// DNS Underscore Admins
@id("MREG.dns_underscore_admin")
permit (
    principal in MREG::Group::"default-dns-underscore-group",
    action == MREG::Action::"dns_underscore_admin_access",
    resource
);

/// We also have a global super admin policy that allows the root super user
/// to do anything to any resource.
@id("global.super_admin_allow_all_policy")
permit (
    principal == User::"super",
    action,
    resource
);
