from django.urls import path

from . import views

urlpatterns = [
        path('dhcphosts/v4/all', views.DhcpHostsAllV4.as_view()),
        path('dhcphosts/v6/all', views.DhcpHostsAllV6.as_view()),
        path('dhcphosts/<ip>/<range>', views.DhcpHostsByRange.as_view()),
]
