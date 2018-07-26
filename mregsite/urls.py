from django.contrib import admin
from django.urls import path
from mreg.api.v1 import views
from rest_framework_swagger.views import get_swagger_view


# Changed from coreapi docs functionality to the django-rest-swagger which looks alot nicer
schema_view = get_swagger_view(title='mreg API')

# The resource keyword argument is used by StrictCRUDMixin to determine the base url for generic views
urlpatterns = [
    path('cnames/', views.CnameList.as_view(), kwargs={'resource': 'cnames'}),
    path('cnames/<pk>', views.CnameDetail.as_view(), kwargs={'resource': 'cnames'}),
    path('hinfopresets/', views.HinfoPresetList.as_view(), kwargs={'resource': 'hinfopresets'}),
    path('hinfopresets/<pk>', views.HinfoPresetDetail.as_view(), kwargs={'resource': 'hinfopresets'}),
    path('hosts/', views.HostList.as_view(), kwargs={'resource': 'hosts'}),
    path('hosts/<pk>', views.HostDetail.as_view(), kwargs={'resource': 'hosts'}),
    path('ipaddresses/', views.IpaddressList.as_view(), kwargs={'resource': 'ipaddresses'}),
    path('ipaddresses/<pk>', views.IpaddressDetail.as_view(), kwargs={'resource': 'ipaddresses'}),
    path('naptrs/', views.NaptrList.as_view(), kwargs={'resource': 'naptrs'}),
    path('naptrs/<pk>', views.NaptrDetail.as_view(), kwargs={'resource': 'naptrs'}),
    path('nameservers/', views.NameServerList.as_view(), kwargs={'resource': 'nameservers'}),
    path('nameservers/<pk>', views.NameServerDetail.as_view(), kwargs={'resource': 'nameservers'}),
    path('ptroverrides/', views.PtrOverrideList.as_view(), kwargs={'resource': 'ptroverrides'}),
    path('ptroverrides/<pk>', views.PtrOverrideDetail.as_view(), kwargs={'resource': 'ptroverrides'}),
    path('srvs/', views.SrvList.as_view(), kwargs={'resource': 'srvs'}),
    path('srvs/<pk>', views.SrvDetail.as_view(), kwargs={'resource': 'srvs'}),
    path('subnets/', views.SubnetList.as_view(), kwargs={'resource': 'subnets'}),
    path('subnets/<ip>/<range>', views.SubnetDetail.as_view(), kwargs={'resource': 'subnets'}),
    path('txts/', views.TxtList.as_view(), kwargs={'resource': 'txts'}),
    path('txts/<pk>', views.TxtDetail.as_view(), kwargs={'resource': 'txts'}),
    path('zones/', views.ZoneList.as_view(), kwargs={'resource': 'zones'}),
    path('zones/<name>', views.ZoneDetail.as_view(), kwargs={'resource': 'zones'}),
    path('zones/<name>/nameservers', views.ZoneNameServerDetail.as_view(), kwargs={'resource': 'zones'}),
    path('zonefiles/<pk>', views.ZoneFileDetail.as_view()),
    path('history/', views.ModelChangeLogList.as_view(), kwargs={'resource': 'model_change_logs'}),
    path('history/<table>/<pk>', views.ModelChangeLogDetail.as_view(), kwargs={'resource': 'model_change_logs'}),
    path('admin/', admin.site.urls),
    path('docs/', schema_view),
]

