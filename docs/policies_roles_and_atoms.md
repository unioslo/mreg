# Hostpolicy: Policies, Roles, and Atoms

Hostpolices are built from smaller units called "atoms" and grouped into "roles." These roles are then assigned to "hosts." In short:

- **Atoms:** The smallest building blocks of a host policy.
- **Roles:** Collections (or sets) of atoms. Roles serve as a convenient grouping mechanism to apply multiple policy atoms to hosts.
- **Hosts:** The machines or entities the policies apply to.
- **Labels:** Additional metadata or categorizations that can be attached to roles, potentially for filtering or permission checks.

The relationships can be visualized as:

```

             +-------------------+
             |  HostPolicyAtom   |
             +---------+---------+
                       ^
                       |  Many-to-Many
                       |
             +----------+---------+
             |     HostPolicyRole |
             +-----+-------+------+
                   |       |
                   | M2M   | M2M
                   |       |
                  Hosts   Labels
```

## Key Models

### HostPolicyAtom (models.HostPolicyAtom)

- Represents the smallest indivisible "unit" of a policy. For instance, an atom might represent a particular configuration rule or permission.
- Has a unique name, which cannot clash with any existing role’s name. This mutual exclusivity ensures that if something is named "foo" as an atom, you cannot have a role named "foo" as well.
- Has a Many-to-Many relation in the reverse direction through roles: each HostPolicyAtom can belong to multiple HostPolicyRoles.

### HostPolicyRole (models.HostPolicyRole)

- A role is basically a named collection of atoms. You can think of a role as a "package" or "bundle" of policies (atoms).
- A role has a unique name, which cannot clash with any existing atom’s name.

It can have Many-to-Many relationships with:

- atoms (HostPolicyAtom): defining which atoms make up this role.
- hosts (Host): defining which hosts this role is applied to.
- labels (Label): an additional layer of classification or grouping for roles, which might be used for permission checks or organizational grouping.

### Host (from mreg.models.host)

Represents a machine or system that these policies will be applied to.
Hosts can have multiple roles assigned to them, and thereby inherit the atoms and policies from those roles.

### Labels (from mreg.models.base.Label)

Arbitrary tags or groupings applied to roles. They might be used to control user permissions or to filter sets of roles.

## Relationships Between Models

### Role ↔ Atom: Many-to-Many

A single role can include multiple atoms; a single atom can be part of multiple roles.

### Role ↔ Host: Many-to-Many

A single role can be applied to multiple hosts; a host can have multiple roles.

### Role ↔ Label: Many-to-Many

A role can have zero or more labels attached. Labels are not described in detail here, but presumably add metadata or inform access control checks.

## Validation Rules

Notice that both HostPolicyAtom and HostPolicyRole have validations ensuring that their names do not conflict. This implies the application treats atoms and roles as part of a shared namespace for naming. If an atom is named "webserver_config," you cannot have a role named "webserver_config," and vice versa.

## Signals and Events

The `signals.py` file provides insight into the logic applied whenever these models’ relationships or attributes change. The main idea behind the signals is:

When atoms or hosts are added or removed from a role (Many-to-Many changes) the updated_at field of the role is refreshed to reflect the new state.

Events are sent to a message queue (MQSender) so that external systems can react to changes (e.g. for configuration deployment automation).
When an atom is renamed or deleted:

Associated roles’ timestamps are updated so that the system "knows" something changed.
Events are also sent out to inform external systems of these changes.

### In summary

m2m_changed signals handle updates when Many-to-Many relationships are modified (adding/removing atoms from roles, adding/removing hosts from roles). pre_save/pre_delete signals on atoms ensure that when atoms are renamed or deleted, their related roles are also updated accordingly. post_save/post_delete signals send events when roles or atoms are created or removed.

### Use Cases

#### Creating a New Atom

A user defines a new HostPolicyAtom, perhaps backup_policy_atom. On creation, a signal fires sending an event "atom_created."

#### Adding an Atom to a Role

The user associates backup_policy_atom with main_server_role. This Many-to-Many addition triggers a signal updating main_server_role's updated_at timestamp and sends an event "add_atom_to_role."

#### Assigning a Role to a Host

Assigning main_server_role to a host named host1.example.com triggers a similar chain: update timestamps and send "add_role_to_host" event.

## API and Serialization

The `api/v1/` directory includes serializers and views that provide REST endpoints for these resources:

HostPolicyAtom and HostPolicyRole endpoints allow CRUD operations.

Filtering (via HostPolicyAtomFilterSet and HostPolicyRoleFilterSet) enable searching by properties like name, creation date, or the names of related atoms/hosts.

Special endpoints exist for managing the Many-to-Many relationships, for example:

- `hostpolicy/roles/<name>/atoms/` for listing or adding atoms to a role.
- `hostpolicy/roles/<name>/hosts/` for listing or adding hosts to a role.

Through these endpoints, an external system or user can manage which policies apply to which hosts and track changes over time.

## Permissions

The api/permissions.py file shows that not everyone can modify these roles, atoms, or their relationships. Permissions logic involves:

Checking if a user is a superuser or "hostpolicy_admin."
If not, users get read-only access unless they have NetGroupRegexPermissions that match the labels on roles they want to modify. This ensures a controlled environment where policy adjustments are restricted.

## Conceptual Summary

Imagine you have numerous systems (hosts) and you want to apply certain configuration policies. These policies are broken down into "atoms," the smallest building blocks of configuration. But you usually apply a bundle of these atoms together; that bundle is a "role." Once a role is defined and populated with atoms, you assign it to the relevant hosts. By managing these relationships in Django and signaling changes through message queues, the system ensures that external infrastructure or configuration management tools are always up-to-date with the latest policy structures.

In essence, the Hostpolicy app provides a flexible structure for creating and managing hierarchical policy components (atoms inside roles) and applying them dynamically to a fleet of hosts, while maintaining audit logs, permission checks, and automatic event notifications.
