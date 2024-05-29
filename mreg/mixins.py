from typing import Protocol, Any, Dict, Union
from django.shortcuts import get_object_or_404
from django.http import HttpRequest
from rest_framework.request import Request
from django.db.models import QuerySet


class DetailViewProtocol(Protocol):
    """Protocol that defines the expected methods and attributes for the mixin."""

    request: HttpRequest
    kwargs: Dict[str, Any]
    lookup_field: str

    def get_queryset(self) -> QuerySet[Any]:
        """Method to get the queryset."""
        ...

    def filter_queryset(self, queryset: QuerySet[Any]) -> QuerySet[Any]:
        """Method to filter the queryset."""
        ...

    def check_object_permissions(self, request: HttpRequest, obj: Any) -> None:
        """Method to check object permissions."""
        ...


class LowerCaseLookupMixin:
    """A mixin to make DRF detail view lookup case insensitive."""

    def get_object(self: DetailViewProtocol) -> Any:
        """Returns the object the view is displaying.
        
        This method is overridden to make the lookup case insensitive.

        :returns: The object the view is displaying.
        """
        queryset = self.filter_queryset(self.get_queryset())
        filter_kwargs = {self.lookup_field: self.kwargs[self.lookup_field].lower()}

        obj = get_object_or_404(queryset, **filter_kwargs)

        # May raise a permission denied
        self.check_object_permissions(self.request, obj)

        return obj        

    def get_object_from_request(
            self: DetailViewProtocol, request: Request, field: Union[str, None] = None
        ) -> Union[Any, None]:
        """Return an object from the queryset based on data from the request, if any.
        
        The object is found in the queryset by querying with field = request.data[field]. If the field
        is not defined, and the view offers a self.lookup_field, that field is used as a fallback.

        Note: This is part of the LowerCaseLookupMixin, so the value of the field in request.data will
        be lowercased when querying.

        :param request: The request object.
        :param field: The field to use for the lookup. If None, the view's lookup_field is used. 

        :returns: The object from the queryset or None.

        :raises AttributeError: If no field is specified and the view does not have a lookup_field defined.
        """
        if not field and not self.lookup_field:
            raise AttributeError("If not specifying a field, the view must have lookup_field defined.")

        lfield: str = field if field else self.lookup_field

        if not request.data or not isinstance(request.data, dict):
            return None
        
        if self.lookup_field not in request.data:
            return None
        
        queryset = self.filter_queryset(self.get_queryset())
        filter_kwargs: Dict[str, str] = {lfield: request.data[lfield].lower()}

        return queryset.filter(**filter_kwargs).first()