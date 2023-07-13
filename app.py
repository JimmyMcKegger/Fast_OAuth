import binascii
import hashlib
import hmac
import httpx
import redis
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from os import getenv, urandom
from re import match

load_dotenv()

client_id = getenv("SHOPIFY_CLIENT_ID")
client_secret = getenv("SHOPIFY_CLIENT_SECRET")
scopes = getenv("SHOPIFY_SCOPES")
app_url = getenv("HOST_URL")

r = redis.Redis(host="localhost", port=6379, decode_responses=True)
app = FastAPI()


async def get_access_token(shop, auth_code):
    async with httpx.AsyncClient() as client:
        url = f"https://{shop}/admin/oauth/access_token"
        params = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": auth_code,
        }
        response = await client.post(url, params=params)
        print(response.json())


@app.get("/")
async def root(request: Request):
    # redirect to auth if necessary
    return {"message": "Hello World"}


@app.get("/api/auth")
async def auth(request: Request):
    query_params = dict(request.query_params)
    hmac_value = query_params.pop("hmac", None)
    sorted_params = "&".join(
        [f"{key}={value}" for key, value in sorted(query_params.items())]
    )
    digest = hmac.new(
        client_secret.encode(), sorted_params.encode(), hashlib.sha256
    ).hexdigest()
    shop = query_params.get("shop")
    access_mode = "per-user"

    if hmac_value and hmac.compare_digest(digest, hmac_value):
        nonce = binascii.b2a_hex(urandom(15)).decode("utf-8")
        r.set(shop, nonce)
        redirect_uri = f"{app_url}/confirm"
        redirect_to_shopify = f"https://{shop}/admin/oauth/authorize?client_id={client_id}&scope={scopes}&redirect_uri={redirect_uri}&state={nonce}&grant_options[]={access_mode}"
        return RedirectResponse(redirect_to_shopify)
    else:
        raise HTTPException(status_code=401, detail="Invalid HMAC")


@app.get("/confirm")
async def login(request: Request):
    shop_origin = request.query_params.get("shop")
    pattern = r"[\w\-]*\.myshopify\.com"
    if not match(pattern, shop_origin):
        raise HTTPException(status_code=400, detail="Invalid shop domain")

    authorization_code = request.query_params.get("code")

    # Check the HMAC
    hmac_value = request.query_params.get("hmac")
    sorted_params = "&".join(
        [f"{key}={value}" for key, value in sorted(request.query_params.items())]
    )
    request_nonce = request.query_params.get("state")
    provided_nonce = r.get(shop_origin)

    if provided_nonce != request_nonce:
        raise HTTPException(status_code=400, detail="Wrong nonce value")

    await get_access_token(shop_origin, authorization_code)

    # install mandatory webhooks now

    # redirect to app
    return "success"


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
