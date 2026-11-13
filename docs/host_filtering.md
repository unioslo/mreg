# Filtering host records

## Hosts in a CIDR

```http
GET /api/v1/hosts/?ip_range=158.36.188.0/23
GET /api/v1/hosts/?ip_range=2001:db8::/48
```

## Hosts by name

```http
GET /api/v1/hosts/?name__in=host1.example.org,host2.example.org
```
