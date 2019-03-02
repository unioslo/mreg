from django.urls import path

from . import views

urlpatterns = [
    path('token-logout/', views.TokenLogout.as_view()),
    path('token-auth/', views.ObtainExpiringAuthToken.as_view()),
]
