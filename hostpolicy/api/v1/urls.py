from django.urls import path

from . import views

urlpatterns = [
    path('hostpolicy/atoms/', views.HostPolicyAtomList.as_view(), name='atom-list'),
    path('hostpolicy/atoms/<name>', views.HostPolicyAtomDetail.as_view(), name='hostpolicyatom-detail'),
    path('hostpolicy/roles/', views.HostPolicyRoleList.as_view(), name='role-list'),
    path('hostpolicy/roles/<name>', views.HostPolicyRoleDetail.as_view(), name='role-detail'),
    path('hostpolicy/roles/<name>/atoms/', views.HostPolicyRoleAtomsList.as_view()),
    path('hostpolicy/roles/<name>/atoms/<atom>', views.HostPolicyRoleAtomsDetail.as_view()),
    path('hostpolicy/roles/<name>/hosts/', views.HostPolicyRoleHostsList.as_view()),
    path('hostpolicy/roles/<name>/hosts/<host>', views.HostPolicyRoleHostsDetail.as_view()),
]
