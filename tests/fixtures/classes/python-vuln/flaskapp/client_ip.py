from flask import request


def client_ip():
    return request.access_route[0]
