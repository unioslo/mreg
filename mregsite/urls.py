from django.contrib import admin
from django.urls import include, path

from mreg.api.v1 import views

from rest_framework.schemas import get_schema_view

# Schema view for swagger api documentation
schema_view = get_schema_view(title='mreg API')

urlpatterns = [
    path('api/', include('mreg.api.urls')),
    path('api/v1/', include('hostpolicy.api.v1.urls')),
    path('api/v1/', include('mreg.api.v1.urls')),
    path('admin/', admin.site.urls),
    path('docs/', schema_view),
]
