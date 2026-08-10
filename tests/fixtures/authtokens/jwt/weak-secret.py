import jwt
def sign(p):
    return jwt.encode(p, "secret", algorithm="HS256")
