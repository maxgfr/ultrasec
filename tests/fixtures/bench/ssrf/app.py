import requests
def handler(request):
    url = request.args.get("url")
    return requests.get(url)
