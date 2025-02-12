from django.contrib import admin

# Register your models here.

from .models import ScanReport , Blacklist, BlackListRemovalRequest

admin.site.register(ScanReport)
admin.site.register(Blacklist)
admin.site.register(BlackListRemovalRequest)