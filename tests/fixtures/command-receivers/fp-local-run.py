import subprocess


def run(job, target):
    """An application verb, not subprocess.run — and the file imports subprocess."""
    return f"{job}:{target}"


def handler(request):
    job = request.args.get("job")
    return run(job, "target")


def real(request):
    subprocess.run(["sh", "-c", request.args.get("c")])
