# Network Policies API Documentation

This document describes the **Network Policies API**, which manages **Network Policies**, **Policy Attributes**, and **Communities**, as well as **Hosts** that belong to these communities. Below you will find the conceptual overview, endpoint references, and sample requests and responses.

---

## Table of Contents

- [Network Policies API Documentation](#network-policies-api-documentation)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
    - [Network Policy](#network-policy)
    - [Policy Attributes](#policy-attributes)
    - [Community](#community)
    - [Host Membership](#host-membership)
  - [Authentication and Permissions](#authentication-and-permissions)
  - [Endpoints](#endpoints)
    - [Network Policy Endpoints](#network-policy-endpoints)
      - [List / Create](#list--create)
      - [Retrieve / Update / Delete](#retrieve--update--delete)
    - [Policy Attribute Endpoints](#policy-attribute-endpoints)
      - [List / Create](#list--create-1)
      - [Retrieve / Update / Delete](#retrieve--update--delete-1)
    - [Community Endpoints](#community-endpoints)
      - [List / Create](#list--create-2)
      - [Retrieve / Update / Delete](#retrieve--update--delete-2)
    - [Hosts in a Community](#hosts-in-a-community)
      - [List / Add Host to a Community](#list--add-host-to-a-community)
      - [Retrieve / Remove Host from a Community](#retrieve--remove-host-from-a-community)
  - [Usage Examples](#usage-examples)
  - [Error Handling](#error-handling)
  - [Notes](#notes)
  - [Conclusion](#conclusion)

---

## Overview

### Network Policy

A **Network Policy** is a named entity grouping a set of attributes (via **Policy Attributes**). Policy attributes typically say something about the network, such as whether it is isolated, public, employs DHCP or SLAAC, etc.

- **Name**: Human-readable case insensitive identifier of the policy.
- **Description**: A brief description of the policy.
- **Attributes**: A list of attributes that apply to this policy (see below).

### Policy Attributes

A **Policy Attribute** is a simple boolean flag or marker. Policy Attributes do *not* by themselves define system behavior. Instead, each attribute is a type of marker that can be set for a given policy. These attributes contain no semantic meaning to the system, but are used by other tools to define the behavior of a network policy.

- **Name**: Human-readable case insensitive identifier of the attribute.
- **Description**: A brief description of the attribute.

Note: In `settings.py` the administrators may set `MREG_PROTECTED_POLICY_ATTRIBUTES` set to a list of dictionaries (with `name` and optionally `description` as their fields) to be guaranteed to exist on server startup and protected from deletion. This is useful for attributes that are the site requires to exist at all times.

**Important**:  

- Attributes must first be defined globally (e.g., "isolated," "public," "private") using the **Policy Attribute** endpoints.  
- Then, they are associated with a **Network Policy** and given a value (true/false).  

### Community

A **Community** is a named (case insensitive) collection of **Hosts** within a **single** Network. Each community belongs to exactly one network, enabling further subdivision of hosts within that network. This is typically used for client isolation / segmentation. Communities allow you to group hosts based on function, location, access, or other logical groupings.

### Host Membership

**Hosts** in this system can belong to one Community per network it belongs to. Adding a host to a community requires that at least one of the host’s IP addresses match the network.

Note: Administrators may set `MREG_CREATING_COMMUNITY_REQUIRES_POLICY_WITH_ATTRIBUTES` which will require that a network must have a policy with all the attributes in the list to be able to create a community. `MREG_MAX_COMMUNITES_PER_NETWORK` can be set to limit the number of communities per network. Setting this to 0 will allow an unlimited number of communities.

---

## Authentication and Permissions

- **IsGrantedNetGroupRegexPermission**:  
  Guards most policy and community endpoints, ensuring users have the correct network group permissions.

- **IsSuperOrNetworkAdminMember**:  
  Used for administrative endpoints, such as creating or managing policy attributes. Only superusers or network admins can create, update, or delete attributes.

---

## Endpoints

### Network Policy Endpoints

#### List / Create

**`GET /api/v1/networkpolicies/`**  
**`POST /api/v1/networkpolicies/`**  

- **List (GET)**: Returns all existing policies.
- **Create (POST)**: Creates a new policy with a name and optional attributes (specified by already-created `NetworkPolicyAttribute` IDs).

**Example (POST Request)**:

```json
{
  "name": "SecurePolicy", // This will be turned into "securepolicy" internally
  "attributes": [
    {
      "attribute": 1,   // ID of an existing NetworkPolicyAttribute
      "value": true
    }
  ]
}
```

- Response: 201 Created, plus a Location header pointing to the new policy.

#### Retrieve / Update / Delete

**`GET /api/v1/networkpolicies/<pk>/`**
**`PATCH /api/v1/networkpolicies/<pk>/`**
**`DELETE /api/v1/networkpolicies/<pk>/`**

- **GET:** Retrieve details of a specific policy (including associated attributes and communities).
- **PATCH (or PUT):** Update the name or attributes.
- **DELETE:** Remove the policy entirely (and any related communities).

### Policy Attribute Endpoints

#### List / Create

**`GET /api/v1/networkpolicyattributes/`**
**`POST /api/v1/networkpolicyattributes/`**

- **List (GET):** Returns all attributes (global definitions).
- **Create (POST):** Define a new policy attribute with a name and description that can be used in policies.

**Example (POST Request):**

```json
{
  "name": "Isolated",
  "description": "Marks network isolation if set to true."
}
```

- Response: 201 Created

Note: All names are case-insensitive and will be converted to lowercase internally.

#### Retrieve / Update / Delete

**`GET /api/v1/networkpolicyattributes/<pk>/`**
**`PATCH /api/v1/networkpolicyattributes/<pk>/`**
**`DELETE /api/v1/networkpolicyattributes/<pk>/`**

- **GET:** View details about a specific attribute.
- **PATCH (or PUT):** Update attribute name or description.
- **DELETE:** Remove the attribute definition entirely.

### Community Endpoints

#### List / Create

**`GET /api/v1/networks/<network>/communities/`**
**`POST /api/v1/networks/<network>/communities/`**

- **List (GET):** Retrieve all communities associated with a specific network.
- **Create (POST):** Create a new community under a specific network.

**Example (POST Request):**

```json
{
  "name": "FrontendServers",
  "description": "Handles all front-end servers."
}
```

- Response: 201 Created

Note: All community names are case-insensitive and will be converted to lowercase internally.

#### Retrieve / Update / Delete

**`GET /api/v1/networks/<network>/communities/<cpk>`**
**`PATCH /api/v1/networks/<network>/communities/<cpk>`**
**`DELETE /api/v1/networks/<network>/communities/<cpk>`**

- **GET:** Get details for a specific community.
- **PATCH:** Update the name/description of a community.
- **DELETE:** Remove the community from the network.

**Example (GET Response):**

```json
{
   "id":1,
   "name":"test_community",
   "description":"community desc",
   "hosts":[
      "hostwithcommunity.example.com"
   ],
   "created_at":"2025-01-24T12:24:35.676621+01:00",
   "updated_at":"2025-01-24T12:24:35.676630+01:00"
}
```

### Hosts in a Community

#### List / Add Host to a Community

**`GET /api/v1/networks/<network>/communities/<cpk>/hosts/`**
**`POST /api/v1/networks/<network>/communities/<cpk>/hosts/`**

- **GET:** Lists all hosts assigned to this community.
- **POST:** Associates an existing host with this community if it meets the network criteria.

**Example (POST Request):**

```json
{
  "id": 5  // ID of the existing Host
}
```

Note: At least one of the host’s IP address(es) must belong to the network, otherwise the request will fail with a 400 Bad reqeust error.

#### Retrieve / Remove Host from a Community

**`GET /api/v1/networks/<network>/communities/<cpk>/hosts/<hostpk>`**
**`DELETE /api/v1/networks/<network>/communities/<cpk>/hosts/<hostpk>`**

- **GET:** Retrieves details of a specific host in this community.
- **DELETE:** Removes that host from the community.

## Usage Examples

Creating a Network Policy Attribute

**`POST /api/v1/networkpolicyattributes/`**

```json
{
  "name": "Isolated",
  "description": "Marks network isolation if set to true."
}
```

Note: All names are case-insensitive and will be converted to lowercase internally.

Creating a Network Policy

**`POST /api/v1/networkpolicies/`**

```json
{
  "name": "SecurePolicy",
  "attributes": [
    { "attribute": 1, "value": true }
  ]
}
```

Creating a Community under a Network

**`POST /api/v1/networks/1/communities/`**

```json
{
  "name": "BackendServices",
  "description": "All backend service hosts."
}
```

1. Adding a Host to a Community

**`POST /api/v1/networks/1/communities/2/hosts/`**

```json
{
  "id": 42
}
```

The system checks if Host `42` has at least one IP addresses belonging to networks configured under Network Policy `1`.

Response: 201 Created (on success), or 409 Conflict (if the host’s IP doesn’t match).

## Error Handling

- **400 Bad request**: Invalid request data or failed validation (e.g., IP mismatch when adding a host to a community).
- **403 Forbidden**: Insufficient permissions for the requested operation.
- **404 Not Found**: Policy, community, attribute, or host not found in the system.

## Notes

Fetching a network will now include the policy object in full, as such:

**`GET /api/v1/networks/10.0.0.0/24`**

```json
{
   "id":1,
   "excluded_ranges":[
      
   ],
   "policy":{
      "id":1,
      "name":"test_policy",
      "attributes":[
         
      ],
      "created_at":"2025-01-24T12:24:35.664231+01:00",
      "updated_at":"2025-01-24T12:24:35.664241+01:00"
    },
    "communities":[
        {
          "id":1,
          "name":"test_community",
          "global_name":"community01", // Only set if MREG_MAP_GLOBAL_COMMUNITY_NAMES is True 
          "description":"community desc", 
          "policy":1,
          "hosts":[
              "hostwithcommunity.example.com"
          ],
          "created_at":"2025-01-24T12:24:35.676621+01:00",
          "updated_at":"2025-01-24T12:24:35.676630+01:00"
        }
    ],
    "created_at":"2025-01-24T12:24:35.683213+01:00",
    "updated_at":"2025-01-24T12:24:35.683219+01:00",
    "network":"10.0.0.0/24",
    "description":"test_network",
    "vlan":"None",
    "dns_delegated":false,
    "category":"",
    "location":"",
    "frozen":false,
    "reserved":3
}
```

## Conclusion

The Network Policies API enables administrators to:

- Define Global Attributes (e.g., “isolated”, “public”, “private”, "dhcp", "dhcpv6", etc).
- Create Policies referencing those attributes and associating them with boolean values.
- Assign policies to networks.
- Subdivide a network into Communities, grouping hosts for more granular network management.
- Assign Hosts to Communities under the correct network, provided their IP addresses match the appropriate networks.
