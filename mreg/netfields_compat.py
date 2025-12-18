"""
Compatibility layer for netfields with Django 5.2+

Django 6.0 introduced a breaking change where custom ORM expressions must return
params as a tuple from as_sql(). The netfields library's NetFieldDecoratorMixin
returns tuples from process_lhs(), but Django's BuiltinLookup.as_sql() now calls
params.extend(rhs_params), which fails on tuples.

This is documented in Django 6.0 release notes under "Backwards incompatible changes":
https://docs.djangoproject.com/en/dev/releases/6.0/#custom-orm-expressions-should-return-params-as-a-tuple
But, earlier versions also support lists and we've seen failures on Django 5.2,
so we apply the patch for all versions we now support (5.2+).

The issue is that while Django expects tuples from as_sql(), it converts the
process_lhs() return to a list internally, but netfields' custom process_lhs()
bypasses this conversion.

If netfields is updated to a version that is compatible with Django 6.0+, this patch
can be removed.
"""
def patch_netfields_for_django52():
    """
    Patch netfields lookups to ensure params are lists for Django 5.2+ compatibility.
    
    This is needed because Django 5.2's BuiltinLookup.as_sql() calls
    params.extend(rhs_params), which requires params to be a list. The netfields
    library's NetFieldDecoratorMixin.process_lhs() returns tuples, causing
    AttributeError: 'tuple' object has no attribute 'extend'.
    """
    try: 
        from netfields.lookups import NetFieldDecoratorMixin # noqa
    except ImportError:
        # netfields not installed
        return

    # Store the original process_lhs method
    original_process_lhs = NetFieldDecoratorMixin.process_lhs

    def patched_process_lhs(self, qn, connection, lhs=None):
        """
        Wrapper around NetFieldDecoratorMixin.process_lhs that ensures
        params are returned as a list instead of a tuple.
        """
        lhs_string, lhs_params = original_process_lhs(self, qn, connection, lhs)
        # Convert params to list if it's a tuple
        if isinstance(lhs_params, tuple):
            lhs_params = list(lhs_params)
        return lhs_string, lhs_params

    # Replace the method with our patched version
    NetFieldDecoratorMixin.process_lhs = patched_process_lhs
