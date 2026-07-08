import pickle
def handler(request):
    data = request.data
    return pickle.loads(data)
