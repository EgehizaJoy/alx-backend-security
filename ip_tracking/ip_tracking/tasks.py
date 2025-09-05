from celery import shared_task
from django.utils import timezone
from django.db.models import Count
from datetime import timedelta

from .models import RequestLog, SuspiciousIP


@shared_task
def detect_suspicious_ips():
    """
    Runs hourly to detect suspicious IPs based on:
    - More than 100 requests in the past hour
    - Access to sensitive paths (/admin, /login)
    """
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    # 1. Detect IPs exceeding 100 requests/hour
    high_traffic_ips = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values("ip_address")
        .annotate(request_count=Count("id"))
        .filter(request_count__gt=100)
    )

    for entry in high_traffic_ips:
        ip = entry["ip_address"]
        SuspiciousIP.objects.get_or_create(
            ip_address=ip,
            defaults={"reason": f"Exceeded 100 requests/hour ({entry['request_count']})"},
        )

    # 2. Detect IPs accessing sensitive paths
    sensitive_paths = ["/admin", "/login"]
    suspicious_logs = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago,
        path__in=sensitive_paths,
    ).values("ip_address").distinct()

    for log in suspicious_logs:
        ip = log["ip_address"]
        SuspiciousIP.objects.get_or_create(
            ip_address=ip,
            defaults={"reason": "Accessed sensitive path (/admin or /login)"},
        )
