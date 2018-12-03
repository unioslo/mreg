from django.urls import path

from . import views

urlpatterns = [
        path('dhcphosts/v4/all', views.dhcphosts_all_v4),
        path('dhcphosts/v6/all', views.dhcphosts_all_v6),
        path('dhcphosts/<ip>/<range>', views.dhcphosts_by_range),
]
