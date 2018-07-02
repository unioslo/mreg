from django.contrib import admin
from django.urls import path
from django.conf.urls import url
from mreg.api.v1 import views
from rest_framework.urlpatterns import format_suffix_patterns

urlpatterns = [
    url(r'^cname/$', views.CnameList.as_view()),
    url(r'^cname/(?P<pk>[0-9]+)/$', views.CnameDetail.as_view()),
    url(r'^hinfopresets/$', views.HinfoPresetsList.as_view()),
    url(r'^hinfopresets/(?P<pk>[0-9]+)/$', views.HinfoPresetsDetail.as_view()),
    url(r'^hosts/$', views.HostList.as_view()),
    url(r'^hosts/(?P<pk>[0-9]+)/$', views.HostDetail.as_view()),
    url(r'^ipaddresses/$', views.IpaddressList.as_view()),
    url(r'^ipaddresses/(?P<pk>[0-9]+)/$', views.IpaddressDetail.as_view()),
    url(r'^naptr/$', views.NaptrList.as_view()),
    url(r'^naptr/(?P<pk>[0-9]+)/$', views.NaptrDetail.as_view()),
    url(r'^ns/$', views.NsList.as_view()),
    url(r'^ns/(?P<pk>[0-9]+)/$', views.NsDetail.as_view()),
    url(r'^ptroverride/$', views.PtrOverrideList.as_view()),
    url(r'^ptroverride/(?P<pk>[0-9]+)/$', views.PtrOverrideDetail.as_view()),
    url(r'^srv/$', views.SrvList.as_view()),
    url(r'^srv/(?P<pk>[0-9]+)/$', views.SrvDetail.as_view()),
    url(r'^subnets/$', views.SubnetsList.as_view()),
    url(r'^subnets/(?P<pk>[0-9]+)/$', views.SubnetsDetail.as_view()),
    url(r'^txt/$', views.TxtList.as_view()),
    url(r'^txt/(?P<pk>[0-9]+)/$', views.TxtDetail.as_view()),
    url(r'^zones/$', views.ZonesList.as_view()),
    url(r'^zones/(?P<pk>[0-9]+)/$', views.ZonesDetail.as_view()),
    path('admin/', admin.site.urls),
]

urlpatterns = format_suffix_patterns(urlpatterns)
