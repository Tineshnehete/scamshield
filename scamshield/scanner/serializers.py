from rest_framework import serializers
import tldextract
from django.contrib.auth.models import User

from .models import ScanReport , Blacklist , BlackListRemovalRequest , DomainRank

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
    message = serializers.CharField()
    class Meta:
        model = Blacklist
        fields = ['url', 'reason' , "message"]

    def create(self, validated_data):
        validated_data['domain'] = tldextract.extract(validated_data['url']).domain + '.' + tldextract.extract(validated_data['url']).suffix
        validated_data['reported_by'] = self.context['request'].user
        print(validated_data)
        return Blacklist.objects.create(**validated_data)
    
class BlackListRemovalRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlackListRemovalRequest
        fields = ['url', 'domain', 'reason' , "context", "organization" ]    
    def create(self, validated_data):
        validated_data['requested_by'] = self.context['request'].user
        print(validated_data)
        return BlackListRemovalRequest.objects.create(**validated_data)
class DomainRankSerializer(serializers.ModelSerializer):
    class Meta:
        model = DomainRank
        fields = '__all__'


# Serializer for User Registration
class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password')

    def create(self, validated_data):
        # Create the user
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user