from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import (User, ExpiringToken)

admin.site.register(User, UserAdmin)


@admin.register(ExpiringToken)
class AuthTokenAdmin(admin.ModelAdmin):
    list_display = ('key', 'user', 'created', 'last_used')
