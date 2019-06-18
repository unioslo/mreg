from django.contrib import admin
from django.urls import include, path

from rest_framework_swagger.views import get_swagger_view

# Schema view for swagger api documentation
schema_view = get_swagger_view(title='mreg API')

urlpatterns = [
    path('api/', include('mreg.api.urls')),
    path('admin/', admin.site.urls),
    path('docs/', schema_view),
]
