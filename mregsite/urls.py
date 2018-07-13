from django.contrib import admin
from django.urls import path
from mreg.api.v1 import views
from rest_framework.urlpatterns import format_suffix_patterns

urlpatterns = [
    path('cnames/', views.CnameList.as_view()),
    path('cnames/<pk>/', views.CnameDetail.as_view()),
    path('hinfopresets/', views.HinfoPresetsList.as_view()),
    path('hinfopresets/<pk>/', views.HinfoPresetsDetail.as_view()),
    path('hosts/', views.HostList.as_view()),
    path('hosts/<pk>/', views.HostDetail.as_view()),
    path('ipaddresses/', views.IpaddressList.as_view()),
    path('ipaddresses/<pk>/', views.IpaddressDetail.as_view()),
    path('naptrs/', views.NaptrList.as_view()),
    path('naptrs/<pk>/', views.NaptrDetail.as_view()),
    path('nameservers/', views.NsList.as_view()),
    path('nameservers/<pk>/', views.NsDetail.as_view()),
    path('ptroverrides/', views.PtrOverrideList.as_view()),
    path('ptroverrides/<pk>/', views.PtrOverrideDetail.as_view()),
    path('srvs/', views.SrvList.as_view()),
    path('srvs/<pk>/', views.SrvDetail.as_view()),
    path('subnets/', views.SubnetsList.as_view()),
    path('subnets/<ip>/<range>/', views.SubnetsDetail.as_view()),
    path('txts/', views.TxtList.as_view()),
    path('txts/<pk>/', views.TxtDetail.as_view()),
    path('zones/', views.ZonesList.as_view()),
    path('zones/<name>/', views.ZonesDetail.as_view()),
    path('zones/<name>/nameservers/', views.ZonesNsDetail.as_view()),
    path('admin/', admin.site.urls),
]

urlpatterns = format_suffix_patterns(urlpatterns)
