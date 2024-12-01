from rest_framework import generics
from .models import ScamReport
from .serializers import ScamReportSerializer

class ScamReportListCreateView(generics.ListCreateAPIView):
    queryset = ScamReport.objects.all()
    serializer_class = ScamReportSerializer

class ScamReportDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = ScamReport.objects.all()
    serializer_class = ScamReportSerializer
