from flask import request


def client_ip():
    # The app is wrapped in ProxyFix(app.wsgi_app, x_for=1): remote_addr is the client.
    return request.remote_addr
