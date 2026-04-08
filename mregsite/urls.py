from django.contrib import admin
from django.urls import include, path
from django.conf import settings

from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView


swagger_view = SpectacularSwaggerView.as_view(url_name='schema')

urlpatterns = [
    path('api/', include('mreg.api.urls')),
    path('api/v1/', include('hostpolicy.api.v1.urls')),
    path('api/v1/', include('mreg.api.v1.urls')),
    path('admin/', admin.site.urls),
    # Download the schema as a file
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    # Schema UIs
    path('schema/swagger/', swagger_view, name='swagger'),
    path('schema/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    # Legacy alias for /docs/
    path('docs/', swagger_view, name='docs'),
]

if settings.MREG_PROFILING_ENABLED:
    urlpatterns.append(path('silk/', include('silk.urls', namespace='silk')))
