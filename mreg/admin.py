from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from mreg.models.auth import User
from mreg.models.base import ExpiringToken

admin.site.register(User, UserAdmin)


@admin.register(ExpiringToken)
class AuthTokenAdmin(admin.ModelAdmin):
    list_display = ('key', 'user', 'created', 'last_used')
