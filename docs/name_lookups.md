# Lowercase name lookups

`LowerCaseCharField` and its `LowerCaseDNSNameField` subclass store text in
lowercase. Their registered Django lookups also normalize literal query values,
so callers do not need to call `.lower()` before querying.

This applies to direct and chained querysets, `Q` objects, related managers,
lookups spanning joins, and `get_object_or_404()`. It works with ordinary Django
managers; `LowerCaseManager` remains available for compatibility.

```python
Host.objects.get(name="SERVER.EXAMPLE.ORG")
Host.objects.filter(Q(name="SERVER.EXAMPLE.ORG"))
Host.objects.filter(name__in=["SERVER.EXAMPLE.ORG", "OTHER.EXAMPLE.ORG"])
HostGroup.objects.filter(hosts__name="SERVER.EXAMPLE.ORG")
```

## Lookup behavior

| Lookup | Behavior |
| --- | --- |
| `exact`, `gt`, `gte`, `lt`, `lte` | Lowercase literal strings before comparison. |
| `in`, `range` | Lowercase each literal string in the iterable. |
| `contains`, `startswith`, `endswith` | Lowercase literal text; Django still escapes SQL wildcard characters. |
| `regex`, `iregex` | Preserve the pattern, including escapes such as `\D` and `\S`. |
| `iexact`, `icontains`, `istartswith`, `iendswith` | Use Django's case-insensitive lookups unchanged. |

Only lookups against a lowercase field's stored column normalize literals.
Ordinary fields, including Django auth group names used as hostgroup owners,
retain their existing case sensitivity.

Explicit expressions (`F`, `Value`, subqueries) and transforms retain their
normal Django semantics. For example, `name=Value("SERVER.EXAMPLE.ORG")` does not
normalize that expression; use `name__iexact=Value("SERVER.EXAMPLE.ORG")` if a
case-insensitive expression comparison is intended. Mixed `in` lists normalize
their literal strings while preserving expression elements.

Normalization changes query parameters, leaving stored columns unwrapped in SQL.
Existing indexes remain eligible for ordinary exact lookups. Storage behavior
and the database schema are unchanged.
