# Labels

Labels are a top-level concept that provide an additional layer of classification and metadata within the system. While "atoms" represent minimal policy units and "roles" group these atoms into larger policy sets, "labels" serve as tags or categories that can be attached to roles (and potentially other objects) for organizational or access-control purposes.

## What is a Label?

A Label is a named entity with a human-readable description. The Label model enforces a few key constraints:

- **Uniqueness and Format:** Each label has a unique lowercase name. This helps ensure there's a consistent taxonomy of labels that can be easily referenced.
- **Description:** A textual field describes the label's purpose or meaning.

Labels can thus represent concepts like functional areas, environments, departments, or security domains. For example, labels might include finance, production, staging, or webserver, depending on how your organization categorizes hosts and roles.

## How Labels Are Used in mreg

### Applying Labels to Roles

In the hostpolicy code, specifically HostPolicyRole has a Many-to-Many relationship to Label. This means that a single role can have zero, one, or multiple labels.

These labels describe characteristics or intended domains of that role. For example, a role named db_admin_role might be labeled database or internal to indicate it's related to internal database administration policies.

### Filtering and Searching by Labels

In the `api/v1/` endpoints (like LabelList and LabelDetail), as well as filters (like LabelFilterSet), you can filter or retrieve labels by their names. For host policies, filters such as `labels__name__exact` or `labels__name__regex` are used when querying roles. This allows the API consumer to do queries like:

- Find all roles that have a label matching production.
- Retrieve all roles that have labels with names containing db.

This functionality makes it easy to organize and discover roles based on the contexts their labels provide.

### Permission Checks Involving Labels

The permissions.py code for Hostpolicy demonstrates that labels are not just organizational tools; they also tie into the authorization logic. When a non-superuser attempts to modify a host or role, the code checks:

- Which labels are assigned to that role?
- Does the requesting user have any NetGroupRegexPermission that matches those labels?

In other words, labels can act as a key to unlock modification privileges. If a user doesn't have permission to manipulate roles bearing a certain label, their requests to add/remove hosts or atoms to that role will be denied.

This is a powerful concept: by attaching labels to roles and by setting up permissions that reference these labels, the system can enforce complex, label-based security policies. For example:

- Roles labeled sensitive might be restricted to a particular group of administrators.
- Roles labeled dev might be open to a broader set of users with matching permissions.

### Technical Details Linking Labels to Permissions

The permission code (IsSuperOrHostPolicyAdminOrReadOnly) checks whether a user is a superuser or hostpolicy admin. If not, and the user tries to modify (not just read) a role:

- It pulls the labels on that role via `role_labels = HostPolicyRole.objects.filter(name=name).values_list('labels__name', flat=True)`.
- It then looks up NetGroupRegexPermission objects associated with the user to see if these permissions cover any of the role’s labels.

Only if there’s a match does the user gain write access.

## In Summary

- Labels are independent, top-level objects with unique names.
- Roles can be assigned multiple labels.
- Labels serve both as organizational tools (for searching and grouping roles) and as hooks in the permission system (to grant or restrict modifications).

### In practical terms

- From an API perspective, you can create and manage labels separately and you can assign these labels to roles.
- When users try to change roles (like adding atoms or hosts), the label assignments to that role determine if the user’s existing permissions allow that change.

Thus, labels are a key component in organizing and controlling the complexity of host policies. They allow fine-grained access control and filtering, building on top of the more fundamental concepts of roles and atoms.
