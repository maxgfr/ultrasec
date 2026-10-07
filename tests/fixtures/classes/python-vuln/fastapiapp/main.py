from fastapi import FastAPI

from .export import router

app = FastAPI()
app.include_router(router)
