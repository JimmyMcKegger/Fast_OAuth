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
from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta

load_dotenv()

client_id = getenv("SHOPIFY_CLIENT_ID")
client_secret = getenv("SHOPIFY_CLIENT_SECRET")
scopes = getenv("SHOPIFY_SCOPES")
app_url = getenv("HOST_URL")

engine = create_engine("sqlite:///shops.db", echo=True)
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()


# define model
class ShopTokens(Base):
    __tablename__ = "shop_tokens"
    shop = Column(String, primary_key=True)
    access_token = Column(String)
    scope = Column(String)
    expires_at = Column(DateTime)
    associated_user_scope = Column(String)
    session = Column(String)
    account_number = Column(String)
    associated_user = Column(JSON)


# create db
Base.metadata.create_all(engine)

# start redis-server in a terminal
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
        token_data = response.json()

        # Calculate the expiration time
        expires_in = int(token_data["expires_in"])
        expires_at = datetime.now() + timedelta(seconds=expires_in)

        token_entry = ShopTokens(
            shop=shop,
            access_token=token_data["access_token"],
            scope=token_data["scope"],
            expires_at=expires_at,
            associated_user_scope=token_data["associated_user_scope"],
            session=token_data["session"],
            account_number=token_data["account_number"],
            associated_user=token_data["associated_user"],
        )
        session.add(token_entry)
        session.commit()


async def get_access_token_from_db(shop):
    token_entry = session.query(ShopTokens).filter_by(shop=shop).first()
    if token_entry:
        token_data = {
            "access_token": token_entry.access_token,
            "scope": token_entry.scope,
            "expires_in": token_entry.expires_in,
            "associated_user_scope": token_entry.associated_user_scope,
            "session": token_entry.session,
            "account_number": token_entry.account_number,
            "associated_user": token_entry.associated_user,
        }
        return token_data
    return None


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
