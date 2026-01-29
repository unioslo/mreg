from django.urls import path

from . import views

urlpatterns = [
    path('token-logout/', views.TokenLogout.as_view()),
    path('token-auth/', views.ObtainExpiringAuthToken.as_view()),
    path('token-is-valid/', views.TokenIsValid.as_view()),
    path('meta/user', views.UserInfo.as_view()),
    path('meta/version', views.MregVersion.as_view()),
    path('meta/libraries', views.MetaVersions.as_view()),
    path('meta/metrics', views.MetricsView.as_view()),
    path('meta/health/heartbeat', views.HealthHeartbeat.as_view()),
    path('meta/health/ldap', views.HealthLDAP.as_view()),
]
