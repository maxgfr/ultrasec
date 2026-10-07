from django.http import HttpResponse


def transfer(request):
    request.user.account.transfer(request.POST["to"], request.POST["amount"])
    return HttpResponse(status=204)
