// MREG permissions example.

@id("MREG.admins_policy")
permit (
    principal in MREG::Group::"admins",
    action in
        [MREG::Action::"create_host",
         MREG::Action::"delete_host",
         MREG::Action::"view_host",
         MREG::Action::"edit_host"],
    resource is Host
);

// Webadmins can edit, delete, or create hosts with a name label containing "webserver", and the IP
// address must be in the range 192.168.1.0/24
@id("MREG.webadmins_policy")
permit (
    principal in MREG::Group::"webadmins",
    action in
        [MREG::Action::"edit_host",
         MREG::Action::"delete_host",
         MREG::Action::"create_host"],
    resource is Host
)
when
{
    resource.nameLabels.contains("webserver") &&
    resource.ip.isInRange("192.168.1.0/24")
};

// Users can only view hosts
@id("MREG.users_policy")
permit (
    principal in MREG::Group::"users",
    action == MREG::Action::"view_host",
    resource is Host
);

// Charlie does not get to delete hosts, no matter what.
@id("MREG.charlie_forbid_delete_host_policy")
forbid (
    principal == MREG::User::"charlie",
    action == MREG::Action::"delete_host",
    resource is Host
);

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
    resource.ip.isInRange("192.168.1.0/24") ||
    resource.ip.isInRange("10.0.0.0/8")
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
@id("MREG.is_superuser")
permit (
    principal in MREG::Group::"default-super-group",
    action, // Superadmins don't care what the action is
    resource
);

/// Normal (?) admins
@id("MREG.is_admin")
permit (
    principal in MREG::Group::"default-admin-group",
    action == MREG::Action::"is_admin",
    resource
);

/// Host Policy Admins 
@id("MREG.is_hostpolicy_admin")
permit (
    principal in MREG::Group::"default-hostpolicyadmin-group",
    action == MREG::Action::"is_hostpolicy_admin",
    resource
);

/// DNS Wildcard Admins 
@id("MREG.is_dns_wildcard_admin")
permit (
    principal in MREG::Group::"default-dns-wildcard-group",
    action == MREG::Action::"is_dns_wildcard_admin",
    resource
);

/// DNS Underscore Admins
@id("MREG.is_dns_underscore_admin")
permit (
    principal in MREG::Group::"default-dns-underscore-group",
    action == MREG::Action::"is_dns_underscore_admin",
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