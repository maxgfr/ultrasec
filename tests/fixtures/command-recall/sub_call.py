import subprocess


def handler(request):
    cmd = request.args.get("c")
    subprocess.call(cmd, shell=True)
    subprocess.check_output(cmd, shell=True)
