from django.db import models

class ScamReport(models.Model):
    url = models.URLField(max_length=200)
    is_scam = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
