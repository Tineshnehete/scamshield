from django.shortcuts import render
from django.utils import timezone
from datetime import timedelta, datetime

import json
# Create your views here.
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework import views , generics , response , status, filters, permissions

from .serializers import ScanUrlReqSerializer, ReportSpamUrlSerializer , BlacklistSerializer , BlackListRemovalRequestSerializer, UserRegistrationSerializer
from .models import Blacklist , BlackListRemovalRequest ,ScanReport
from .utils.scanner import Scanner

class ScanUrlView( views.APIView):
    serializer_class = ScanUrlReqSerializer
    def post(self , request):
        url = request.data.get('url')
        if url:
            # check if the url is already scanned in last month
            if ScanReport.objects.filter(url=url , created_at__gte=timezone.now() - timedelta(days=30)  
                                         ).exists():
                report = ScanReport.objects.get(url=url)
                return response.Response({'url': url, "report": json.loads(report.report)
                                      }, status=status.HTTP_200_OK)
            scanner = Scanner()
            report = scanner.scan(url)
            # convert report to json
            #  Object of type datetime is not JSON serializable fir this err getting fo loowingvline
            # covert all datime to string
            print(report)
            for key in report:
                if isinstance(report[key], datetime):
                    report[key] = report[key].strftime('%Y-%m-%d %H:%M:%S')
            for key in report.get("whois", {}):
                if isinstance(report["whois"][key], datetime):
                    report.get("whois")[key] = report["whois"][key].strftime('%Y-%m-%d %H:%M:%S')
            for key in report.get("ssl", {}):
                if isinstance(report["ssl"][key], datetime):
                    report["ssl"][key] = report["ssl"][key].strftime('%Y-%m-%d %H:%M:%S')

            report1 = json.dumps(report)

            ScanReport.objects.create(url=url, trust_score=report['trust_score'], report=report1)

            
            return response.Response({'url': url, "report": report
                                      }, status=status.HTTP_200_OK)
        else:
            return response.Response({'error': 'URL not provided'}, status=status.HTTP_400_BAD_REQUEST)


# view for reporting the spam urls
class ReportSpamUrlView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ReportSpamUrlSerializer
    def post(self , request):
        serializer = ReportSpamUrlSerializer(data=request.data , context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return response.Response({
                'message': 'URL reported as spam'
            }, status=status.HTTP_200_OK)
        else:
            return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class SearchBlacklistView(generics.ListAPIView):
    serializer_class = BlacklistSerializer

    filter_backends = [filters.SearchFilter]
    search_fields = ['url', 'domain']

    def get_queryset(self):
        return Blacklist.objects.all()
    
class BlackListRemovalRequestView(generics.CreateAPIView):
    serializer_class = BlackListRemovalRequestSerializer
    def post(self , request):
        serializer = BlackListRemovalRequestSerializer(data=request.data , context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return response.Response({
                'message': 'Request submitted successfully'
            }, status=status.HTTP_200_OK)
        else:
            return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)






# Registration view
@api_view(['POST'])
def register(request):
    if request.method == 'POST':
        serializer = UserRegistrationSerializer(data=request.data)

        # Validate and create the user
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                'message': 'User successfully created',
                'user': {
                    'username': user.username,
                    'email': user.email
                }
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
