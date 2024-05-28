from typing import Protocol, Any, Dict, Union
from django.shortcuts import get_object_or_404
from django.http import HttpRequest
from django.http.request import QueryDict
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

    def get_object_from_request(self: DetailViewProtocol, request: Request) -> Union[Any, None]:
        """Return the object defined by the key lookup_field in request.data, if any.

        Note: This is part of the LowerCaseLookupMixin, so the value of the lookup_field
        in request.data will be lowercased.

        :param request: The request object.

        :returns: The object from the queryset or None.
        """
        if not self.lookup_field:
            raise AttributeError("lookup_field must be defined.")
        
        if not request.data or not isinstance(request.data, QueryDict):
            return None
        
        if self.lookup_field not in request.data:
            return None
        
        queryset = self.filter_queryset(self.get_queryset())
        filter_kwargs: Dict[str, str] = {self.lookup_field: request.data[self.lookup_field].lower()}

        return queryset.filter(**filter_kwargs).first()