from django.contrib import admin
from django.urls import path
from django.conf.urls import url
from mreg.api.v1 import views
from rest_framework.urlpatterns import format_suffix_patterns

urlpatterns = [
    url(r'^hosts/$', views.HostList.as_view()),
    url(r'^hosts/(?P<pk>[0-9]+)/$', views.HostDetail.as_view()),
    url(r'^cname/$', views.CnameList.as_view()),
    url(r'^cname/(?P<pk>[0-9]+)/$', views.CnameDetail.as_view()),
    url(r'^ns/$', views.NsList.as_view()),
    url(r'^ns/(?P<pk>[0-9]+)/$', views.NsDetail.as_view()),
    path('admin/', admin.site.urls),
]

urlpatterns = format_suffix_patterns(urlpatterns)
