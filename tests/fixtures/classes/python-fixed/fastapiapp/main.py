from fastapi import FastAPI
from secure import Secure

from .export import router

secure_headers = Secure.with_default_headers()
app = FastAPI()
app.include_router(router)
