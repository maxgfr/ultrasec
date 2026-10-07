from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def transfer(request):
    request.user.account.transfer(request.POST["to"], request.POST["amount"])
    return HttpResponse(status=204)
