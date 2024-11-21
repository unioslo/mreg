from django.urls import path

from . import views

urlpatterns = [
    path('token-logout/', views.TokenLogout.as_view()),
    path('token-auth/', views.ObtainExpiringAuthToken.as_view()),
    path('meta/version', views.MregVersion.as_view()),
    path('meta/heartbeat', views.MetaHeartbeat.as_view()),
    path('meta/libraries', views.MetaVersions.as_view()),
]
