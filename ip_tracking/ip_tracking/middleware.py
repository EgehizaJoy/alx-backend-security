from .models import RequestLog
from django.utils.timezone import now

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get IP address (works even if behind proxy/load balancer if X-Forwarded-For is set)
        ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
        if ip_address:
            ip_address = ip_address.split(',')[0]  # Take first IP in list
        else:
            ip_address = request.META.get('REMOTE_ADDR')

        # Log to database
        RequestLog.objects.create(
            ip_address=ip_address,
            timestamp=now(),
            path=request.path
        )

        # Continue processing request
        response = self.get_response(request)
        return response
