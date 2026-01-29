# Multi-Contact Support Migration Guide

## Overview

This migration adds support for multiple contact email addresses per host, replacing the single `contact` field with a many-to-many relationship to a new `HostContact` model.

## Changes Made

### 1. New Model: `HostContact`

- Location: `mreg/models/host.py`
- Purpose: Store individual contact email addresses that can be shared across multiple hosts
- Fields:
  - `id`: Primary key
  - `email`: EmailField - the contact email address
  - `created_at`: Timestamp
  - `updated_at`: Timestamp

### 2. Updated `Host` Model

- Added `contacts` ManyToManyField relationship to `HostContact`
- Removed deprecated `contact` field
- Added helper methods:
  - `_add_contact(email: str)`: Add a single contact email to the host (internal use, may throw ValidationError from the database layer)
  - `add_contacts(emails: list[str])`: Add multiple contact emails to the host, returning a tuple of (added_emails, already_existing_emails, invalid_emails).
  - `remove_contact(email: str)`: Remove contact email from the host
  - `get_contact_emails()`: Get list of all contact emails

### 3. Migration

#### Migration 0016: `0016_host_contacts.py`

This single migration performs all the necessary changes:

- Creates the `HostContact` model
- Adds the `contacts` ManyToMany field to `Host`
- Migrates existing data from `Host.contact` to `HostContact` instances
- Removes the deprecated `contact` field
- **Reversible**: Can migrate back by copying the first contact to the old field

### 4. API Changes

#### Serializers (`mreg/api/v1/serializers.py`)

- Added `HostContactSerializer` for representing contact objects
- Updated `HostSerializer`:
  - Added `contacts` field – see usage below
  - Added `contact` field (read/write, deprecated) - for full backward compatibility:
    - **Read**: Returns space-separated string of all contact emails
    - **Write**: Accepts single email or space-separated multiple emails, automatically converted to list
  - Updated `create()` and `update()` methods to handle both `contacts` input and deprecated `contact` field
  - Added `to_representation()` override to automatically populate the deprecated `contact` field in GET responses

#### API Usage Examples

**Creating a host with multiple contacts:**

```json
POST /api/v1/hosts/
{
  "name": "server.example.com",
  "contacts": ["admin1@example.com", "admin2@example.com"]
}
```

**Response includes contacts:**

```json
{
  "id": 123,
  "name": "server.example.com",
  "contact": "admin1@example.com admin2@example.com",
  "contacts": [
    {
      "id": 1,
      "email": "admin1@example.com",
      "created_at": "2025-12-10T10:00:00Z",
      "updated_at": "2025-12-10T10:00:00Z"
    },
    {
      "id": 2,
      "email": "admin2@example.com",
      "created_at": "2025-12-10T10:00:00Z",
      "updated_at": "2025-12-10T10:00:00Z"
    }
  ]
}
```

**Updating contacts (replaces all contacts):**

```json
PATCH /api/v1/hosts/server.example.com/
{
  "contacts": ["newadmin@example.com"]
}
```

**Clearing all contacts:**

```json
PATCH /api/v1/hosts/server.example.com/
{
  "contacts": []
}
```

**Using deprecated contact field (backward compatibility):**

```json
PATCH /api/v1/hosts/server.example.com/
{
  "contact": "admin@example.com"
}
```

**Or with multiple contacts (space-separated):**

```json
PATCH /api/v1/hosts/server.example.com/
{
  "contact": "admin1@example.com admin2@example.com"
}
```

Note: The deprecated `contact` field is automatically converted to the new `contacts` input internally. Space-separated emails are split into a list. If both `contact` and `contacts` are provided, `contact` is ignored.

#### Filters (`mreg/api/v1/filters.py`)

- Added `contacts__email` filter for searching by contact email (recommended)
- Maintained backward-compatible `contact` filter (deprecated) - aliased to `contacts__email`
- Examples:
  - **New format**: `GET /api/v1/hosts/?contacts__email=admin@example.com`
  - **New format**: `GET /api/v1/hosts/?contacts__email__icontains=admin`
  - **Deprecated format**: `GET /api/v1/hosts/?contact=admin@example.com` (still works, aliased to contacts__email)
  - **Deprecated format**: `GET /api/v1/hosts/?contact__icontains=admin` (still works)

### 5. API Compatibility

The API maintains full backward compatibility for old clients:

#### Write Operations (POST/PATCH)

**Recommended (new format):**

- Use `contacts` field with a list of email addresses
- Supports multiple contacts: `{"contacts": ["admin1@example.com", "admin2@example.com"]}`
- Supports single contact: `{"contacts": ["admin@example.com"]}` or `{"contacts": "admin@example.com"}` (multipart)
- Supports clearing contacts: `{"contacts": []}`

**Deprecated (old format - still works):**

- Use `contact` field with email string(s): `{"contact": "admin@example.com"}` or `{"contact": "admin1@example.com admin2@example.com"}`
- Single email is automatically converted to a single-item list internally
- Space-separated emails are automatically split and converted to list internally
- If both `contact` and `contacts` are provided, `contact` is ignored
- Supports both single and multiple contacts via space-separated format

#### Read Operations (GET)

**Recommended (new format):**

- The `contacts` field returns a list of full contact objects
- Each contact object includes: `id`, `email`, `created_at`, `updated_at`
- Example: `"contacts": [{"id": 1, "email": "admin@example.com", "created_at": "...", "updated_at": "..."}]`

**Deprecated (old format - still provided for backward compatibility):**

- The `contact` field returns a space-separated string of all contact emails
- Example: `"contact": "admin1@example.com admin2@example.com"`
- Empty string if no contacts: `"contact": ""`
- This field is provided automatically in all GET responses for backward compatibility

#### Filter Operations

**Recommended (new format):**

- `contacts__email` - exact match on contact email
- `contacts__email__icontains` - case-insensitive partial match
- All standard Django filter lookups supported: exact, iexact, contains, icontains, startswith, endswith, etc.

**Deprecated (old format - still works):**

- `contact` - aliased to `contacts__email` (exact match)
- `contact__icontains` - aliased to `contacts__email__icontains`
- All filter lookups (`contact__*`) are aliased to corresponding `contacts__email__*` filters

#### Update Behavior

- **PATCH/PUT with `contacts`**: Replaces ALL existing contacts with the new list
- **PATCH/PUT with `contact`** (single email): Replaces ALL existing contacts with a single-item list
- **PATCH/PUT with `contact`** (space-separated): Replaces ALL existing contacts with the parsed list
- **Not providing contact fields**: Leaves existing contacts unchanged
- **Empty list `[]`**: Clears all contacts

**Important**: Standard PATCH/PUT operations replace the entire contact list, which can lead to race conditions when multiple clients attempt to add/remove contacts simultaneously, as they all read the existing list first. To address this, atomic contact operation endpoints are provided below.

### 6. Atomic Contact Operations

To prevent race conditions when multiple clients need to modify contacts, atomic operation endpoints are provided:

#### List Contacts

```bash
GET /api/v1/hosts/{hostname}/contacts/
```

Returns a list of all contacts for the host:

```json
[
  {
    "id": 1,
    "email": "admin1@example.com",
    "created_at": "2025-12-10T10:00:00Z",
    "updated_at": "2025-12-10T10:00:00Z"
  },
  {
    "id": 2,
    "email": "admin2@example.com",
    "created_at": "2025-12-10T10:00:00Z",
    "updated_at": "2025-12-10T10:00:00Z"
  }
]
```

#### Add Contacts (Atomic)

```bash
POST /api/v1/hosts/{hostname}/contacts/
Content-Type: application/json

{
  "emails": ["newadmin@example.com", "monitor@example.com"]
}
```

Response (200 OK):

```json
{
  "added": ["newadmin@example.com", "monitor@example.com"],
  "already_exists": []
}
```

If some emails already exist:

```json
{
  "added": ["newadmin@example.com"],
  "already_exists": ["monitor@example.com"]
}
```

**Benefits:**

- Atomically adds contacts without reading the full list first
- No race condition - multiple clients can add contacts simultaneously
- Returns clear feedback about which emails were added vs already existed, but does not fail if some or all already exist

#### Remove Contacts (Atomic)

**Remove specific contacts:**

```bash
DELETE /api/v1/hosts/{hostname}/contacts/
Content-Type: application/json

{
  "emails": ["oldadmin@example.com", "retired@example.com"]
}
```

Response (200 OK):

```json
{
  "removed": ["oldadmin@example.com", "retired@example.com"],
  "not_found": []
}
```

If some emails don't exist:

```json
{
  "removed": ["oldadmin@example.com"],
  "not_found": ["retired@example.com"]
}
```

**Clear all contacts:**

To remove all contacts without specifying individual emails, simply omit the `emails` parameter:

```bash
DELETE /api/v1/hosts/{hostname}/contacts/
Content-Type: application/json

{}
```

Response (200 OK):

```json
{
  "removed": ["admin1@example.com", "admin2@example.com", "admin3@example.com"]
}
```

**Benefits:**

- Atomically removes contacts without reading the full list first
- No race condition - multiple clients can remove contacts simultaneously
- Returns clear feedback about which emails were removed vs didn't exist
- Convenient clear-all operation when no emails parameter is provided

#### When to Use Atomic Operations

Use the atomic endpoints (`/hosts/{hostname}/contacts/`) when:

- Multiple clients may modify contacts simultaneously
- You want to add contacts without replacing the entire list
- You want to remove specific contacts without affecting others
- You need to avoid race conditions

Use standard PATCH/PUT (`/hosts/{hostname}/`) when:

- You want to replace the entire contact list
- You're making multiple changes to the host and want a single transaction
- Single-client scenarios where race conditions aren't a concern

#### Summary of Backward Compatibility

The implementation provides **full backward compatibility** for the old `contact` field:

1. **Reading (GET)**: Returns `contact` field with space-separated emails (e.g., `"contact": "email1 email2"`)
2. **Writing (POST/PATCH)**: Accepts `contact` field with single or space-separated emails
3. **Filtering**: All `contact` and `contact__*` filters work (aliased to `contacts__email`)
4. **Zero breaking changes**: Old clients continue to work without modification

## Next Steps: Update Client Applications

### Update Client Applications

1. Update all client applications to use `contacts` for writes
2. Update all client applications to read from `contacts` field
3. Update any custom queries to use `contacts__email` instead of `contact`
4. Monitor for any issues

(Note, the old `contact` field will remain available for backward compatibility indefinitely, but it is recommended to migrate to the new fields for future-proofing.)

## Rollback Procedure

If you need to rollback to the old single-contact structure:

```bash
python manage.py migrate mreg 0015_network_max_communities_and_more
```

The reverse migration will:

1. Recreate the `contact` field on the `Host` model
2. Copy the first contact from each host back to the `contact` field (data loss for additional contacts)
3. Remove the `contacts` ManyToMany field and the deprecated `contact` field
4. Delete the `HostContact` model and associated data
  
## Benefits

1. **Multiple contacts per host**: Hosts can have multiple responsible persons
2. **Reusable contacts**: Same person can be contact for multiple hosts
3. **Better data normalization**: Contact emails stored once, referenced many times
4. **Backward compatible**: Smooth transition with no breaking changes initially
5. **Extensible**: Easy to add more contact-related fields in the future (name, phone, etc.)

## Future Enhancements

Potential future improvements:

- Add fields like `name` and `phone` to `HostContact` for contact person's name and phone number?
- Add `role` or `notification_preferences` for alerting configuration?
