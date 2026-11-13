# Filtering host records

`GET /api/v1/hosts/` returns complete host records, including their IP addresses,
contacts, DNS records, groups and roles. Filters can be combined; a host must
match all supplied filters.

## Hosts in a CIDR

```http
GET /api/v1/hosts/?ip_range=158.36.188.0/23
GET /api/v1/hosts/?ip_range=2001:db8::/48
```

`ip_range` accepts any IPv4 or IPv6 CIDR. It does not need to exist as a registered
MREG network: it may select part of one network or span several networks. Host
bits are masked (`158.36.188.10/23` selects `158.36.188.0/23`). A bare IP address
selects that address, like a `/32` or `/128`.

The `/` and `:` in these query values can be left unencoded. URL-encoded values
also work, so `ip_range=158.36.188.0%2F23` is equivalent to the first example.

A host matches when at least one of its IP addresses falls inside the CIDR,
including its first and last addresses. Each matching host is returned once,
with its complete record and all addresses, including addresses outside the
CIDR. Hosts referenced only by a PTR override do not match. This uses the same
IP-address membership as `used_host_list`, whose response is unchanged.

```bash
curl --fail --silent --show-error --get \
  -H "Authorization: Token $TOKEN" \
  --data-urlencode "ip_range=158.36.188.0/23" \
  --data-urlencode "page_size=1000" \
  "https://mreg.uio.no/api/v1/hosts/"
```

The response has the usual `count`, `next`, `previous` and `results` fields.
Follow `next` until it is null to retrieve every result. The default page size
is 100 and the maximum is 1,000.

## Hosts by name

```http
GET /api/v1/hosts/?name__in=host1.example.org,host2.example.org
```

`name__in` accepts comma-separated names. Matching is case-insensitive, missing
names are omitted, and repeated names do not duplicate results. Combine it with
`ip_range` to select only the named hosts that have an address in the CIDR.

## Invalid filters

The host list returns HTTP 400 for unknown query parameters, malformed CIDRs,
invalid numeric filter values, or explicitly empty `ip_range` and `name__in`
filters. Previously, unsupported filters such as `name__in` were silently ignored
and could return unrelated hosts. Omit a filter to request an unrestricted listing.

Existing pagination, ordering, search and format query parameters remain
accepted. Supported host filters are listed in the generated OpenAPI schema.
