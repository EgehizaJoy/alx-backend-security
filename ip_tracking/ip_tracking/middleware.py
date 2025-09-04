from django.http import HttpResponseForbidden
from django.core.cache import cache
from ipgeolocation import IpGeoLocation
from .models import RequestLog,BlockedIP
from django.utils.timezone import now

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.geo = IpGeoLocation()  # initialize the library

    def __call__(self, request):
        # Get IP address (works even if behind proxy/load balancer if X-Forwarded-For is set)
        ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
        if ip_address:
            ip_address = ip_address.split(',')[0]  # Take first IP in list
        else:
            ip_address = request.META.get('REMOTE_ADDR')
            
        # Block if IP is in blacklist
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Your IP has been blocked.")    
        
        # Try to get cached geolocation (24h cache)
        geo_data = cache.get(f"geo:{ip_address}")

        if not geo_data:
            try:
                result = self.geo.get_geolocation(ip_address)
                geo_data = {
                    "country": result.get("country_name"),
                    "city": result.get("city"),
                }
                cache.set(f"geo:{ip_address}", geo_data, 60 * 60 * 24)  # 24h
            except Exception:
                geo_data = {"country": None, "city": None}
                
        # Log to database
        RequestLog.objects.create(
            ip_address=ip_address,
            timestamp=now(),
            path=request.path,
              country=geo_data.get("country"),
            city=geo_data.get("city"),
        )

        # Continue processing request
        response = self.get_response(request)
        return response
