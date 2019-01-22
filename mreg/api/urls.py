from django.urls import path

from . import views

urlpatterns = [
    path('token-auth/', views.ObtainExpiringAuthToken.as_view()),
]
