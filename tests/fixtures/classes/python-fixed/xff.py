def client_ip(request):
    # One trusted proxy: the client is the hop it appended, the last one.
    return request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[-1].strip()
