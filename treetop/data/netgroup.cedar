// Generated from the normalized MREG API policy snapshot. Do not edit by hand.

@id("MREG.generated.netgroup_ip_72fdb3c3e854")
permit (
    principal in MREG::Group::"dummygroup",
    action in
        [MREG::Action::"host_create",
        MREG::Action::"host_update",
        MREG::Action::"host_delete",
        MREG::Action::"host_contacts_create",
        MREG::Action::"host_contacts_delete",
        MREG::Action::"ipaddress_create",
        MREG::Action::"ipaddress_update",
        MREG::Action::"ipaddress_delete",
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
        MREG::Action::"bacnet_id_delete"],
    resource
)
when {
    resource has nameLabels &&
    resource.nameLabels.contains("netgroup_5ffe5b162fe5") &&
    resource has ip &&
    (resource.ip.isInRange(ip("11.22.33.0/24")))
};

@id("MREG.generated.netgroup_hostname_72fdb3c3e854")
permit (
    principal in MREG::Group::"dummygroup",
    action in
        [MREG::Action::"cname_create",
        MREG::Action::"cname_update",
        MREG::Action::"cname_delete"],
    resource is MREG::Cname
)
when {
    resource has nameLabels &&
    resource.nameLabels.contains("netgroup_5ffe5b162fe5")
};

@id("MREG.generated.netgroup_ip_06d46be4843b")
permit (
    principal in MREG::Group::"testgroup",
    action in
        [MREG::Action::"host_create",
        MREG::Action::"host_update",
        MREG::Action::"host_delete",
        MREG::Action::"host_contacts_create",
        MREG::Action::"host_contacts_delete",
        MREG::Action::"ipaddress_create",
        MREG::Action::"ipaddress_update",
        MREG::Action::"ipaddress_delete",
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
        MREG::Action::"bacnet_id_delete"],
    resource
)
when {
    resource has nameLabels &&
    resource.nameLabels.contains("netgroup_5ffe5b162fe5") &&
    resource has ip &&
    (resource.ip.isInRange(ip("10.0.0.0/24")) ||
     resource.ip.isInRange(ip("10.1.0.0/25")) ||
     resource.ip.isInRange(ip("192.168.1.0/24")) ||
     resource.ip.isInRange(ip("192.168.2.1/32")) ||
     resource.ip.isInRange(ip("2001:db8::/64")) ||
     resource.ip.isInRange(ip("2002:db9::/64")))
};

@id("MREG.generated.netgroup_hostname_06d46be4843b")
permit (
    principal in MREG::Group::"testgroup",
    action in
        [MREG::Action::"cname_create",
        MREG::Action::"cname_update",
        MREG::Action::"cname_delete"],
    resource is MREG::Cname
)
when {
    resource has nameLabels &&
    resource.nameLabels.contains("netgroup_5ffe5b162fe5")
};

@id("MREG.generated.netgroup_ip_39b7f3522b17")
permit (
    principal in MREG::Group::"webadmins",
    action in
        [MREG::Action::"host_create",
        MREG::Action::"host_update",
        MREG::Action::"host_delete",
        MREG::Action::"host_contacts_create",
        MREG::Action::"host_contacts_delete",
        MREG::Action::"ipaddress_create",
        MREG::Action::"ipaddress_update",
        MREG::Action::"ipaddress_delete",
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
        MREG::Action::"bacnet_id_delete"],
    resource
)
when {
    resource has nameLabels &&
    resource.nameLabels.contains("netgroup_6eb5380aba41") &&
    resource has ip &&
    (resource.ip.isInRange(ip("192.168.1.0/24")))
};

@id("MREG.generated.netgroup_hostname_39b7f3522b17")
permit (
    principal in MREG::Group::"webadmins",
    action in
        [MREG::Action::"cname_create",
        MREG::Action::"cname_update",
        MREG::Action::"cname_delete"],
    resource is MREG::Cname
)
when {
    resource has nameLabels &&
    resource.nameLabels.contains("netgroup_6eb5380aba41")
};

@id("MREG.generated.netgroup_network_828db597e176")
permit (
    principal in MREG::Group::"dummygroup",
    action in
        [MREG::Action::"community_create",
        MREG::Action::"community_update",
        MREG::Action::"community_delete",
        MREG::Action::"host_create",
        MREG::Action::"host_delete"],
    resource
)
when {
    resource has network &&
    (resource.network == "11.22.33.0/24")
};

@id("MREG.generated.netgroup_network_781caa6738a6")
permit (
    principal in MREG::Group::"testgroup",
    action in
        [MREG::Action::"community_create",
        MREG::Action::"community_update",
        MREG::Action::"community_delete",
        MREG::Action::"host_create",
        MREG::Action::"host_delete"],
    resource
)
when {
    resource has network &&
    (resource.network == "10.0.0.0/24" ||
     resource.network == "10.1.0.0/25" ||
     resource.network == "192.168.1.0/24" ||
     resource.network == "192.168.2.1/32" ||
     resource.network == "2001:db8::/64" ||
     resource.network == "2002:db9::/64")
};

@id("MREG.generated.netgroup_network_b04d124aeecc")
permit (
    principal in MREG::Group::"webadmins",
    action in
        [MREG::Action::"community_create",
        MREG::Action::"community_update",
        MREG::Action::"community_delete",
        MREG::Action::"host_create",
        MREG::Action::"host_delete"],
    resource
)
when {
    resource has network &&
    (resource.network == "192.168.1.0/24")
};

@id("MREG.generated.hostpolicy_role_9856da2c249d")
permit (
    principal in MREG::Group::"dummygroup",
    action == MREG::Action::"hostpolicy_role_host_membership_update",
    resource == MREG::HostPolicyRole::"role1"
)
when {
    resource has nameLabels &&
    resource.nameLabels.contains("netgroup_5ffe5b162fe5") &&
    resource has ip &&
    (resource.ip.isInRange(ip("11.22.33.0/24")))
};

@id("MREG.generated.hostpolicy_role_2b9b9645d997")
permit (
    principal in MREG::Group::"testgroup",
    action == MREG::Action::"hostpolicy_role_host_membership_update",
    resource == MREG::HostPolicyRole::"role1"
)
when {
    resource has nameLabels &&
    resource.nameLabels.contains("netgroup_5ffe5b162fe5") &&
    resource has ip &&
    (resource.ip.isInRange(ip("10.0.0.0/24")) ||
     resource.ip.isInRange(ip("10.1.0.0/25")) ||
     resource.ip.isInRange(ip("192.168.1.0/24")) ||
     resource.ip.isInRange(ip("192.168.2.1/32")) ||
     resource.ip.isInRange(ip("2001:db8::/64")) ||
     resource.ip.isInRange(ip("2002:db9::/64")))
};

@id("MREG.generated.hostpolicy_role_fec5919a9dae")
permit (
    principal in MREG::Group::"webadmins",
    action == MREG::Action::"hostpolicy_role_host_membership_update",
    resource == MREG::HostPolicyRole::"web"
)
when {
    resource has nameLabels &&
    resource.nameLabels.contains("netgroup_6eb5380aba41") &&
    resource has ip &&
    (resource.ip.isInRange(ip("192.168.1.0/24")))
};
