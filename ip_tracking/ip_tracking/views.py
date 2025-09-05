from django.shortcuts import render

# Create your views here.
from django.http import JsonResponse
from ratelimit.decorators import ratelimit

# Anonymous users: 5 requests/minute
# Authenticated users: 10 requests/minute

@ratelimit(key='ip', rate='5/m', block=True)
@ratelimit(key='user_or_ip', rate='10/m', block=True)
def login_view(request):
    """
    Example sensitive endpoint (mock login).
    Rate limited differently for anonymous vs authenticated users.
    """
    return JsonResponse({"message": "Login attempt recorded."})
