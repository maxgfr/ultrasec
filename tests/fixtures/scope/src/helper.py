from flask import request
import subprocess


def read_name():
    return request.args.get("name")


def run_fixed():
    # A different function entirely: the source above cannot reach this.
    return subprocess.check_output("uptime", shell=True)


def run_user():
    target = request.args.get("host")
    return subprocess.check_output("ping -c1 " + target, shell=True)
