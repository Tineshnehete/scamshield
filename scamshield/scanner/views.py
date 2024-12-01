from django.shortcuts import render
import json
# Create your views here.

from rest_framework import views , generics , response , status
from .serializers import ScanUrlReqSerializer
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
