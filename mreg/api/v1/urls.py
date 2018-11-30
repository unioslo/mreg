from django.urls import path

from . import views

urlpatterns = [
        path('dhcphosts/v4/all', views.ListDHCPHosts.as_view(), kwargs={'hosts': 'v4-all'}),
        path('dhcphosts/v6/all', views.ListDHCPHosts.as_view(), kwargs={'hosts': 'v6-all'}),
        path('dhcphosts/<ip>/<range>', views.ListDHCPHosts.as_view()),
]
