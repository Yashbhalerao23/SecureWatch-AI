from rest_framework.views import APIView
from rest_framework.response import Response


class AnalyzeLogAPIView(APIView):
    def post(self, request):
        return Response({'message': 'AI analysis endpoint'})


class BatchAnalyzeAPIView(APIView):
    def post(self, request):
        return Response({'message': 'Batch AI analysis endpoint'})


class AIConfigAPIView(APIView):
    def get(self, request):
        return Response({'message': 'AI config endpoint'})
