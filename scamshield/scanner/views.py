from django.shortcuts import render
import json
# Create your views here.

from rest_framework import views , generics , response , status, filters

from .serializers import ScanUrlReqSerializer, ReportSpamUrlSerializer , BlacklistSerializer
from .models import Blacklist
from .utils.scanner import Scanner

class ScanUrlView( views.APIView):
    serializer_class = ScanUrlReqSerializer
    def post(self , request):
        url = request.data.get('url')
        if url:
            scanner = Scanner()
            report = scanner.scan(url)
            
            return response.Response({'url': url, "report": report
                                      }, status=status.HTTP_200_OK)
        else:
            return response.Response({'error': 'URL not provided'}, status=status.HTTP_400_BAD_REQUEST)


# view for reporting the spam urls
class ReportSpamUrlView(views.APIView):
    serializer_class = ReportSpamUrlSerializer
    def post(self , request):
        serializer = ReportSpamUrlSerializer(data=request.data)
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
    search_fields = ['url']

    def get_queryset(self):
        return Blacklist.objects.all()
    

    