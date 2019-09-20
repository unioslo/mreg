from django.shortcuts import get_object_or_404

from rest_framework import status
from rest_framework.exceptions import MethodNotAllowed
from rest_framework.response import Response


class M2MPermissions:

    def perform_m2m_alteration(self, method, instance):
        self.check_m2m_update_permission(self.request)
        method(instance)

    def check_m2m_update_permission(self, request):
        for permission in self.get_permissions():
            if not permission.has_m2m_change_permission(request, self):
                self.permission_denied(request)


class M2MDetail:
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
        obj = get_object_or_404(queryset, name=self.kwargs[self.lookup_field])
        return obj

    def get_queryset(self):
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


class M2MList:

    def get_queryset(self):
        self.object = get_object_or_404(self.cls,
                                        name=self.kwargs[self.lookup_field])
        self.m2mrelation = getattr(self.object, self.m2m_field)
        return self.m2mrelation.all().order_by('name')

    def post(self, request, *args, **kwargs):
        qs = self.get_queryset()
        if "name" in request.data:
            name = request.data['name']
            if qs.filter(name=name).exists():
                content = {'ERROR': f'{name} already in {self.m2m_field}'}
                return Response(content, status=status.HTTP_409_CONFLICT)
            try:
                instance = self.m2m_object.objects.get(name=name)
            except self.m2m_object.DoesNotExist:
                content = {'ERROR': f'"{name}" does not exist'}
                return Response(content, status=status.HTTP_404_NOT_FOUND)
            self.perform_m2m_alteration(self.m2mrelation.add, instance)
            location = request.path + instance.name
            return Response(status=status.HTTP_201_CREATED, headers={'Location': location})
        else:
            content = {'ERROR': 'No name provided'}
            return Response(content, status=status.HTTP_400_BAD_REQUEST)
