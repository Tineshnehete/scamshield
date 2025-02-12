from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
# Create your models here.

class ScanReport(models.Model):
    """
    Model to store the scan report of a URL
    """
    url = models.URLField(max_length=200)
    trust_score = models.FloatField()
    report = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url

class Blacklist(models.Model):
    """
    Model to store the blacklisted URLs
    """
    url = models.URLField(max_length=1000)
    domain = models.CharField(max_length=255)
    reported_by = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')

    ], default='pending', max_length=20)

    reason = models.TextField()
    def __str__(self):
        return self.url

class BlackListRemovalRequest(models.Model):
    """
    Model to store the blacklisted URL removal requests
    """
    url = models.URLField(max_length=1000)
    domain = models.CharField(max_length=255)
    organization = models.CharField(max_length=255)
    context = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')

    ], default='pending', max_length=20)

    reason = models.TextField()
    requested_by = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    def __str__(self):
        return self.url

class DomainRank(models.Model):
    """
    Model to store the rank of a domain
    """
    domain_name = models.CharField(max_length=255, unique=True)
    rank = models.IntegerField()

    def __str__(self):
        return self.domain_name
    
    @staticmethod
    def get_rank(domain_name):
        """
        Method to get the rank of a domain

        Args:
        domain_name : str : domain name

        Returns:
        int : rank of the domain
        """
        try:
            domain = DomainRank.objects.get(domain_name=domain_name)
            return domain.rank
        except DomainRank.DoesNotExist:
            return 0
        except Exception as e:
            return 0
        
        


# signals


# signal to approve the blacklisted URL
@receiver(post_save, sender=BlackListRemovalRequest)
def approve_blacklist(sender, instance, created, **kwargs):
    """
    Signal to approve the blacklisted URL
    """
    if instance.status == 'approved':
        Blacklist.objects.filter(url=instance.url).delete()
        BlackListRemovalRequest.objects.filter(url=instance.url).delete()