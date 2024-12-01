from django.db import models

# Create your models here.

class ScanReport(models.Model):
    """
    Model to store the scan report of a URL
    """
    url = models.URLField(max_length=200)
    is_scam = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url

class Blacklist(models.Model):
    """
    Model to store the blacklisted URLs
    """
    url = models.URLField(max_length=1000)
    domain = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')

    ], default='pending', max_length=20)

    reason = models.TextField()
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
        
        
