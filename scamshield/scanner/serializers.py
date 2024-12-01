from rest_framework import serializers

from .models import ScanReport , Blacklist

class ScamReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanReport
        fields = '__all__'
class ScanUrlReqSerializer(serializers.Serializer):
    url = serializers.URLField()

class BlacklistSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blacklist
        fields = '__all__'

        