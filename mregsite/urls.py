from django.contrib import admin
from django.urls import path
from mreg.api.v1 import views
from rest_framework.urlpatterns import format_suffix_patterns

urlpatterns = [
    path('cname/', views.CnameList.as_view()),
    path('cname/<pk>/', views.CnameDetail.as_view()),
    path('hinfopresets/', views.HinfoPresetsList.as_view()),
    path('hinfopresets/<pk>/', views.HinfoPresetsDetail.as_view()),
    path('hosts/', views.HostList.as_view()),
    path('hosts/<pk>/', views.HostDetail.as_view()),
    path('ipaddress/', views.IpaddressList.as_view()),
    path('ipaddress/<pk>/', views.IpaddressDetail.as_view()),
    path('naptr/', views.NaptrList.as_view()),
    path('naptr/<pk>/', views.NaptrDetail.as_view()),
    path('nameservers/', views.NsList.as_view()),
    path('nameservers/<pk>/', views.NsDetail.as_view()),
    path('ptroverride/', views.PtrOverrideList.as_view()),
    path('ptroverride/<pk>/', views.PtrOverrideDetail.as_view()),
    path('srv/', views.SrvList.as_view()),
    path('srv/<pk>/', views.SrvDetail.as_view()),
    path('subnets/', views.SubnetsList.as_view()),
    path('subnets/<pk>/', views.SubnetsDetail.as_view()),
    path('txt/', views.TxtList.as_view()),
    path('txt/<pk>/', views.TxtDetail.as_view()),
    path('zones/', views.ZonesList.as_view()),
    path('zones/<pk>/', views.ZonesDetail.as_view()),
    path('zones/<pk>/nameservers/', views.ZonesNsDetail.as_view()),
    path('admin/', admin.site.urls),
]

urlpatterns = format_suffix_patterns(urlpatterns)
