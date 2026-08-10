from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def webhook(request):
    return None
