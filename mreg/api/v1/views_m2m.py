from abc import ABC, abstractmethod
from typing import ClassVar

from django.db.models import Model
from django.shortcuts import get_object_or_404

from rest_framework import status
from rest_framework.exceptions import MethodNotAllowed, NotFound, ValidationError
from rest_framework.response import Response

from mreg.api.errors import Conflict
from mreg.api.responses import created_response
from mreg.utils import display_name


class M2MPermissions:

    def perform_m2m_alteration(self, method, instance):
        self.check_m2m_update_permission(self.request)
        method(instance)

    def check_m2m_update_permission(self, request):
        for permission in self.get_permissions():
            if not permission.has_m2m_change_permission(request, self):
                self.permission_denied(request)

# NOTE: in the absence of abstract class vars in Python, we simply mark
# these classes as ABC to signal that they are abstract and should not be 
# instantiated directly. There is nothing on runtime that prevents this,
# but it lets us check for the presence of ABC in tests to ensure that
# class vars are set correctly on all subclasses.

class M2MBase(ABC):
    cls: ClassVar[type[Model]]
    lookup_field: ClassVar[str]
    m2m_field: ClassVar[str]
    lookup_url_kwarg: ClassVar[str | None] = None


class M2MDetail(M2MBase, ABC):
    """
    get:
    Returns details for the specified m2mrelation member.

    patch:
    Not allowed.

    delete:
    Delete the specified m2mrelation member.
    """

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field
        lookup_value = self.kwargs[lookup_url_kwarg]
        model = queryset.model
        try:
            return queryset.get(name=lookup_value)
        except model.DoesNotExist:
            raise self.member_not_found(model, lookup_value)

    def member_not_found(self, model, lookup_value) -> NotFound:
        """Build the 404 error for a member that isn't in this relation."""
        if model.objects.filter(name=lookup_value).exists():
            return NotFound(f"'{lookup_value}' is not a member of '{self.object.name}'.")
        return NotFound(f"{display_name(model)} '{lookup_value}' does not exist.")

    def get_queryset(self):
        if 'name' not in self.kwargs:
            return self.cls.objects.none()
        self.object = get_object_or_404(self.cls, name=self.kwargs['name'])
        self.m2mrelation = getattr(self.object, self.m2m_field)
        return self.m2mrelation.all()

    # Not sure why this is needed, but GET on a detail bombs out without it, and
    # it is exactly the same function as in DRF's mixins.py.
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def patch(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_m2m_alteration(self.m2mrelation.remove, instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class M2MList(M2MBase, ABC):
    
    m2m_create_if_missing: bool = False
    """Create the related object if it doesn't exist."""

    m2m_object: type[Model]


    def get_queryset(self):
        lookup_url_kwarg = getattr(self, "lookup_url_kwarg", None) or self.lookup_field
        if lookup_url_kwarg not in self.kwargs:
            return self.cls.objects.none()
        self.object = get_object_or_404(self.cls,
                                        name=self.kwargs[lookup_url_kwarg])
        self.m2mrelation = getattr(self.object, self.m2m_field)
        return self.m2mrelation.all().order_by('name')

    def post(self, request, *args, **kwargs):
        qs = self.get_queryset()
        if "name" in request.data:
            name = request.data['name']
            if qs.filter(name=name).exists():
                raise Conflict(f'{name} already in {self.m2m_field}')
            if self.m2m_create_if_missing:
                instance, created = self.m2m_object.objects.get_or_create(name=name)
            else:
                try:
                    instance = self.m2m_object.objects.get(name=name)
                except self.m2m_object.DoesNotExist:
                    raise NotFound(
                        f"{display_name(self.m2m_object)} '{name}' does not exist."
                    )
            self.perform_m2m_alteration(self.m2mrelation.add, instance)
            return created_response(
                request,
                self.get_serializer(instance),
                instance.name,
            )
        else:
            raise ValidationError({"name": "No name provided"})
