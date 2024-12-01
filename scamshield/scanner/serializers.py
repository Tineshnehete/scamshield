from rest_framework import serializers
import tldextract

from .models import ScanReport , Blacklist

class ScanReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanReport
        fields = '__all__'
class ScanUrlReqSerializer(serializers.Serializer):
    url = serializers.URLField()

class BlacklistSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blacklist
        fields = '__all__'

class ReportSpamUrlSerializer(serializers.Serializer):
    url = serializers.URLField()
    reason = serializers.CharField()
    class Meta:
        model = Blacklist
        fields = '__all__'

    def create(self, validated_data):
        validated_data['domain'] = tldextract.extract(validated_data['url']).domain + '.' + tldextract.extract(validated_data['url']).suffix
        return Blacklist.objects.create(**validated_data)