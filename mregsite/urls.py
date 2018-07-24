from django.contrib import admin
from django.urls import path
from mreg.api.v1 import views
from rest_framework.urlpatterns import format_suffix_patterns

# Ex: Making a new IP address is a POST request to /ipaddresses | NB! Requires HOSTNAME (ForeignKey)
#     Changing an existing IP address is a PATCH request to /ipaddresses/<ip>/
#     Deleting an existing IP address is a DELETE request to /ipaddresses/<ip>/
#
# Equivalent for other fields.
#
# To access specific field for a given host <hostname>, use queries:
# /hosts/<hostname>?ipaddress
#

urlpatterns = [
    path('cnames/', views.CnameList.as_view(), kwargs={'resource': 'cnames'}),
    path('cnames/<pk>', views.CnameDetail.as_view(), kwargs={'resource': 'cnames'}),
    path('hinfopresets/', views.HinfoPresetsList.as_view(), kwargs={'resource': 'hinfopresets'}),
    path('hinfopresets/<pk>', views.HinfoPresetsDetail.as_view(), kwargs={'resource': 'hinfopresets'}),
    path('hosts/', views.HostList.as_view(), kwargs={'resource': 'hosts'}),
    path('hosts/<pk>', views.HostDetail.as_view(), kwargs={'resource': 'hosts'}),
    path('ipaddresses/', views.IpaddressList.as_view(), kwargs={'resource': 'ipaddresses'}),
    path('ipaddresses/<pk>', views.IpaddressDetail.as_view(), kwargs={'resource': 'ipaddresses'}),
    path('naptrs/', views.NaptrList.as_view(), kwargs={'resource': 'naptrs'}),
    path('naptrs/<pk>', views.NaptrDetail.as_view(), kwargs={'resource': 'naptrs'}),
    path('nameservers/', views.NsList.as_view(), kwargs={'resource': 'nameservers'}),
    path('nameservers/<pk>', views.NsDetail.as_view(), kwargs={'resource': 'nameservers'}),
    path('ptroverrides/', views.PtrOverrideList.as_view(), kwargs={'resource': 'ptroverrides'}),
    path('ptroverrides/<pk>', views.PtrOverrideDetail.as_view(), kwargs={'resource': 'ptroverrides'}),
    path('srvs/', views.SrvList.as_view(), kwargs={'resource': 'srvs'}),
    path('srvs/<pk>', views.SrvDetail.as_view(), kwargs={'resource': 'srvs'}),
    path('subnets/', views.SubnetsList.as_view(), kwargs={'resource': 'subnets'}),
    path('subnets/<ip>/<range>', views.SubnetsDetail.as_view(), kwargs={'resource': 'subnets'}),
    path('txts/', views.TxtList.as_view(), kwargs={'resource': 'txts'}),
    path('txts/<pk>', views.TxtDetail.as_view(), kwargs={'resource': 'txts'}),
    path('zones/', views.ZonesList.as_view(), kwargs={'resource': 'zones'}),
    path('zones/<name>', views.ZonesDetail.as_view(), kwargs={'resource': 'zones'}),
    path('zones/<name>/nameservers', views.ZonesNsDetail.as_view(), kwargs={'resource': 'zones'}),
    path('zonefiles/<pk>', views.ZoneFileDetail.as_view()),
    path('history/', views.ModelChangeLogsList.as_view(), kwargs={'resource': 'model_change_logs'}),
    path('history/<table>/<pk>', views.ModelChangeLogsDetail.as_view(), kwargs={'resource': 'model_change_logs'}),
    path('admin/', admin.site.urls),
]

urlpatterns = format_suffix_patterns(urlpatterns)
