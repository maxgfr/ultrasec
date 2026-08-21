import subprocess


def nightly(target):
    subprocess.run(["sync", target])
