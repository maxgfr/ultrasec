import json
def handler(request):
    data = request.data
    return json.loads(data)
