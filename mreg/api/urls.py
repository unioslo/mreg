from django.urls import include, path

from . import views

urlpatterns = [
    path('v1/', include('mreg.api.v1.urls')),
    path('token-logout/', views.TokenLogout.as_view()),
    path('token-auth/', views.ObtainExpiringAuthToken.as_view()),
]
