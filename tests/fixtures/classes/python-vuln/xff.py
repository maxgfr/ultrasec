def client_ip(request):
    return request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
