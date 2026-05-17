from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .scanner import scan_website


class WebScanAPIView(APIView):
    """API endpoint for website scanning"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        url = request.data.get('url')
        if not url:
            return Response({'error': 'URL required'}, status=status.HTTP_400_BAD_REQUEST)
        
        result = scan_website(url)
        return Response(result)


@login_required
def web_scanner_view(request):
    """Web scanner page"""
    result = None
    
    if request.method == 'POST':
        url = request.POST.get('url')
        if url:
            result = scan_website(url)
    
    return render(request, 'web_scanner/scan.html', {'result': result})
