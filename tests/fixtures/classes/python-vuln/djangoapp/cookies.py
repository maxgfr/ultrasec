from django.http import JsonResponse


def login_done(request, token):
    response = JsonResponse({"ok": True})
    response.set_cookie("sid", token)
    return response
