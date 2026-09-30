"""Literal-value normalization for lookups on lowercase fields."""

from django.db.models import lookups
from django.db.models.expressions import Col


class LowerCaseLiteralLookupMixin:
    """Normalize literals only when comparing directly against a stored column.

    Django has already resolved joins and Q objects by the time a lookup is
    constructed. Registering these lookups on a field therefore covers all
    querysets without parsing field paths or rewriting query trees.
    """

    def get_prep_lookup(self):
        if (
            isinstance(self.lhs, Col)
            and not hasattr(self.rhs, "resolve_expression")
            and not hasattr(self.rhs, "as_sql")
        ):
            if getattr(self, "get_db_prep_lookup_value_is_iterable", False):
                # Copy the iterable, including mixed literal/expression lists.
                # Normalize before Django wraps literals in Value expressions.
                self.rhs = [self._lowercase_literal(value) for value in self.rhs]
            else:
                self.rhs = self._lowercase_literal(self.rhs)
        return super().get_prep_lookup()

    @staticmethod
    def _lowercase_literal(value):
        return value.lower() if isinstance(value, str) else value


class LowerCaseExact(LowerCaseLiteralLookupMixin, lookups.Exact):
    pass


class LowerCaseIn(LowerCaseLiteralLookupMixin, lookups.In):
    pass


class LowerCaseRange(LowerCaseLiteralLookupMixin, lookups.Range):
    pass


class LowerCaseGreaterThan(LowerCaseLiteralLookupMixin, lookups.GreaterThan):
    pass


class LowerCaseGreaterThanOrEqual(LowerCaseLiteralLookupMixin, lookups.GreaterThanOrEqual):
    pass


class LowerCaseLessThan(LowerCaseLiteralLookupMixin, lookups.LessThan):
    pass


class LowerCaseLessThanOrEqual(LowerCaseLiteralLookupMixin, lookups.LessThanOrEqual):
    pass


class LowerCaseContains(LowerCaseLiteralLookupMixin, lookups.Contains):
    pass


class LowerCaseStartsWith(LowerCaseLiteralLookupMixin, lookups.StartsWith):
    pass


class LowerCaseEndsWith(LowerCaseLiteralLookupMixin, lookups.EndsWith):
    pass


# Regex patterns and explicit case-insensitive lookups keep Django's semantics.
LOWERCASE_LOOKUPS = (
    LowerCaseExact,
    LowerCaseIn,
    LowerCaseRange,
    LowerCaseGreaterThan,
    LowerCaseGreaterThanOrEqual,
    LowerCaseLessThan,
    LowerCaseLessThanOrEqual,
    LowerCaseContains,
    LowerCaseStartsWith,
    LowerCaseEndsWith,
)
