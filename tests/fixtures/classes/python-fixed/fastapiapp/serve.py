import uvicorn
from fastapi import FastAPI
from secure import SecureHeadersMiddleware

app = FastAPI(debug=False)
app.add_middleware(SecureHeadersMiddleware)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", proxy_headers=True, forwarded_allow_ips="10.0.0.1")
