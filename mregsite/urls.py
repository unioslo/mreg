from django.contrib import admin
from django.urls import include, path
from mreg.api.v1 import views
from rest_framework_swagger.views import get_swagger_view


# Schema view for swagger api documentation
schema_view = get_swagger_view(title='mreg API')

# The resource keyword argument is used by StrictCRUDMixin to determine the base url for generic views
urlpatterns = [
    path('', include('mreg.api.v1.urls')),
    path('api/', include('mreg.api.urls')),
    path('admin/', admin.site.urls),
    path('docs/', schema_view),
]

