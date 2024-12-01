from django.db import models

# Create your models here.

class ScanReport(models.Model):
    url = models.URLField(max_length=200)
    is_scam = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url

class Blacklist(models.Model):
    url = models.URLField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    ], default='pending', max_length=20)

    def __str__(self):
        return self.url


class DomainRank(models.Model):
    domain_name = models.CharField(max_length=255, unique=True)
    rank = models.IntegerField()

    def __str__(self):
        return self.domain_name