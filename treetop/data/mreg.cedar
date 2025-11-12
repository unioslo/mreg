// MREG permissions example.

@id("MREG.admins_policy")
permit (
    principal in MREG::Group::"admins",
    action in MREG::Action::"host_access",
    resource is Host
);

// Webadmins can edit, delete, or create hosts with a name label containing "webserver", and the IP
// address must be in the range 192.168.1.0/24
@id("MREG.webadmins_policy")
permit (
    principal in MREG::Group::"webadmins",
    action in MREG::Action::"host_access",
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
    action in [MREG::Action::"host_access"],
    resource is Host
) when {
    resource.ip.isInRange(ip("10.0.0.0/24"))
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

/// Normal (?) admins
@id("MREG.admin")
permit (
    principal in MREG::Group::"default-admin-group",
    action == MREG::Action::"admin_access",
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