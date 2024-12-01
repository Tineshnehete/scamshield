from django.contrib import admin

# Register your models here.

from .models import ScanReport , Blacklist

admin.site.register(ScanReport)
admin.site.register(Blacklist)