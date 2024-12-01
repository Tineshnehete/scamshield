from rest_framework import serializers
from .models import ScamReport

class ScamReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScamReport
        fields = '__all__'
