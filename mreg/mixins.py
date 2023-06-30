from django.shortcuts import get_object_or_404


class LowerCaseLookupMixin:
    """A mixin to make DRF detail view lookup case insensitive."""

    def get_object(self):
        """Returns the object the view is displaying.
        
        This method is overriden to make the lookup case insensitive.
        """

        queryset = self.filter_queryset(self.get_queryset())
        filter_kwargs = {self.lookup_field: self.kwargs[self.lookup_field].lower()}

        obj = get_object_or_404(queryset, **filter_kwargs)

        # May raise a permission denied
        self.check_object_permissions(self.request, obj)

        return obj
