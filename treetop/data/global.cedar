// Global policy kept in its own bundle module because it intentionally applies
// across every namespace and action.
@id("global.super_admin_allow_all_policy")
permit (
    principal == User::"super",
    action,
    resource
);
