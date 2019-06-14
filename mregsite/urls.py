from django.contrib import admin
from django.urls import include, path

from mreg.api.v1 import views  # noqa: F401, get_swagger_view needs this.. ?

from rest_framework_swagger.views import get_swagger_view  # noqa: I100


# Schema view for swagger api documentation
schema_view = get_swagger_view(title='mreg API')

#
urlpatterns = [
    path('api/', include('mreg.api.urls')),
    path('admin/', admin.site.urls),
    path('docs/', schema_view),
]
