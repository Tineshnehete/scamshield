from django.urls import path
from .views import ScamReportListCreateView, ScamReportDetailView

urlpatterns = [
    path('reports/', ScamReportListCreateView.as_view(), name='scam-report-list-create'),
    path('reports/<int:pk>/', ScamReportDetailView.as_view(), name='scam-report-detail'),
]
