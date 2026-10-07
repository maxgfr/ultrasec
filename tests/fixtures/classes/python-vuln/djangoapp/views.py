from django.http import JsonResponse

from .models import User


def export_users(request):
    rows = list(User.objects.all().values("email"))
    return JsonResponse(rows, safe=False)
