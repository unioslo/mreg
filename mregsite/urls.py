from django.contrib import admin
from django.urls import include, path
from django.conf import settings

from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView



urlpatterns = [
    path('api/', include('mreg.api.urls')),
    path('api/v1/', include('hostpolicy.api.v1.urls')),
    path('api/v1/', include('mreg.api.v1.urls')),
    path('admin/', admin.site.urls),
    # Schema UIs
    path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger'),
    path('docs/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    # Download the schema as a file
    path('docs/schema/', SpectacularAPIView.as_view(), name='schema'),

]

if settings.MREG_PROFILING_ENABLED:
    urlpatterns.append(path('silk/', include('silk.urls', namespace='silk')))
