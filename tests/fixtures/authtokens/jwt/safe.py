import os, jwt
SECRET = os.environ["JWT_SECRET"]
def verify(t):
    return jwt.decode(t, SECRET, algorithms=["HS256"])
