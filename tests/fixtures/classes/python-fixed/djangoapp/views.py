from django.http import JsonResponse

from .models import User


def export_users(request):
    rows = list(User.objects.order_by("id").values("email")[:500])
    return JsonResponse(rows, safe=False)
