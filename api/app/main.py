from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, OAuth2
from fastapi.openapi.models import OAuthFlows, OAuthFlowPassword
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from typing import List, Optional
from datetime import time
import requests
import os


from .db import get_session, init_db
from .models import Subscriber
from .schemas.subscriber import SubscriberCreate, SubscriberUpdate, SubscriberInDB


SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hash context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 password bearer flow
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Define OAuth2 flow for Swagger UI
oauth_flow = {"tokenUrl": "login"}
oauth_flows = OAuthFlows(password=OAuthFlowPassword(tokenUrl="/login"))


ADMIN_USERNAME = os.getenv("ADMIN_API_USERNAME")
ADMIN_PASSWORD_HASH = pwd_context.hash(os.getenv("ADMIN_API_PASSWORD"))

# Set your Twitch client ID and secret
client_id = os.getenv("TWITCH_CLIENT_ID")
client_secret = os.getenv("TWITCH_CLIENT_SECRET")

# Set the webhook callback URL
callback_url = "http://localhost:8000"

# Initialize the OAuth token and timestamp
oauth_token = ""
token_timestamp = 0

# Define a function to get an OAuth token
def get_oauth_token():
    global oauth_token, token_timestamp
    if time.time() - token_timestamp > 3000: # 50 minutes
        token_url = "https://id.twitch.tv/oauth2/token"
        params = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials"
        }
        response = requests.post(token_url, params=params)
        response_data = response.json()
        oauth_token = response_data["access_token"]
        token_timestamp = time.time()
    return oauth_token

# Define a function to register the webhook
def register_webhook():
    webhook_url = "https://api.twitch.tv/helix/eventsub/subscriptions"
    headers = {
        "Client-ID": client_id,
        "Authorization": f"Bearer {get_oauth_token()}"
    }
    data = {
        "type": "channel.subscribe",
        "version": "1",
        "condition": {
            "broadcaster_user_id": os.getenv("TWITCH_BROADCASTER_ID")
        },
        "transport": {
            "method": "webhook",
            "callback": callback_url,
            "secret": os.getenv("TWITCH_WEBHOOK_SECRET")
        }
    }
    response = requests.post(webhook_url, headers=headers, json=data)
    response_data = response.json()
    return response_data["id"]



app = FastAPI(
    title="DevOps With Brian - Twitch Sub Board",
    version="0.0.1",
    description="DevOps With Brian - Twitch Sub Board",
    openapi_tags=[],
    components={
        "securitySchemes": {
            "oauth2_scheme": OAuth2(
                flows=OAuthFlows(password=OAuthFlowPassword(tokenUrl="login"))
            )
        }
    },
    security=[{"oauth2_scheme": []}],
)

origins = [
    "http://localhost:3000",
    "http://localhost:8081",
    "http://twitch-sub-ui:3000",
    "http://twitch-sub-ui:80",
    "https://twitch-subs.devopswithbrian.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    await init_db()


# Verify user credentials
def verify_user(username: str, password: str):
    if username == ADMIN_USERNAME and pwd_context.verify(password, ADMIN_PASSWORD_HASH):
        return True
    else:
        return False


# Define a function to check if the current user is an admin
def get_admin_user(current_user: str = Depends(oauth2_scheme)):
    try:
        # Decode the JWT token to get the payload
        payload = jwt.decode(current_user, SECRET_KEY, algorithms=[ALGORITHM])
        # Extract the 'sub' claim (username) from the payload
        username = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Check if the user is an admin
    if username != ADMIN_USERNAME:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    return username


# Authenticate user and generate access token
def authenticate_user(username: str, password: str):
    if verify_user(username, password):
        access_token_expires = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token_payload = {"sub": username, "exp": access_token_expires}
        access_token = jwt.encode(access_token_payload, SECRET_KEY, algorithm=ALGORITHM)
        return {"access_token": access_token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=400, detail="Incorrect username or password")


# Login endpoint
@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    return authenticate_user(form_data.username, form_data.password)


# Protected endpoint
@app.get("/admin-only")
async def admin_only(current_user: str = Depends(oauth2_scheme)):
    try:
        # Decode the JWT token to get the payload
        payload = jwt.decode(current_user, SECRET_KEY, algorithms=[ALGORITHM])
        # Extract the 'sub' claim (username) from the payload
        username = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid access token")
    if username != ADMIN_USERNAME:
        raise HTTPException(status_code=403, detail="Not authorized")
    else:
        return {"message": "Hello, admin!"}


@app.get('/subscribers')
async def get_subscribers(count: int = 100, session: AsyncSession = Depends(get_session)):
    async with session as s:
        stmt = select(Subscriber).order_by(Subscriber.id).limit(count)
        result = await s.execute(stmt)
        subscribers = result.scalars().all()
        return subscribers
   

@app.post('/subscribers', response_model=List[SubscriberInDB])
async def create_subscribers(subscribers: List[SubscriberCreate], session: AsyncSession = Depends(get_session), current_user: str = Depends(get_admin_user)):
    created_subscribers = []
    async with session as s:
        for subscriber in subscribers:
            # Check if the user_id already exists in the database
            stmt = select(Subscriber).filter_by(user_id=subscriber.user_id)
            result = await s.execute(stmt)
            existing_subscriber = result.scalars().first()
            if existing_subscriber:
                # Raise an HTTPException if the user_id already exists
                raise HTTPException(status_code=400, detail="User already exists")
            # Create a new subscriber if the user_id does not exist
            new_subscriber = Subscriber(**subscriber.dict())
            s.add(new_subscriber)
            try:
                await s.commit()
                await s.refresh(new_subscriber)
                created_subscribers.append(new_subscriber)
            except IntegrityError:
                await s.rollback()
                raise HTTPException(status_code=400, detail="Subscriber already exists")
    return created_subscribers


@app.post("/callback")
async def handle_webhook_callback(request: Request, response: Response, session: AsyncSession = Depends(get_session)):
    data = await request.json()
    print(data)
    event_type = request.headers.get("Twitch-Eventsub-Message-Type")
    if event_type == "webhook_callback_verification":
        response.body = data["challenge"].encode()
        response.headers["Content-Type"] = "text/plain"
    elif event_type == "notification":
        # Extract the subscription event data from the payload
        sub_data = data['subscription']
        event_data = data["event"]
        if sub_data['type']:
            if sub_data['type'] == "channel.subscribe":
                print(f"user_name: {event_data['user_name']}")
                print(f"user_id: {event_data['user_id']}")
                print(f"is_gifted: {event_data['is_gift']}")
                created_subscribers = []
                subscribers=[{
                   "user_name": event_data['user_name'],
                   "user_id": event_data['user_id'],
                   "is_gifted": event_data['is_gift']
                }]
                async with session as s:
                    for subscriber in subscribers:
                        # Check if the user_id already exists in the database
                        stmt = select(Subscriber).filter_by(user_id=event_data['user_id'])
                        result = await s.execute(stmt)
                        existing_subscriber = result.scalars().first()
                        if existing_subscriber:
                            # Raise an HTTPException if the user_id already exists
                            raise HTTPException(status_code=400, detail="User already exists")
                        # Create a new subscriber if the user_id does not exist
                        new_subscriber = Subscriber(**subscriber)
                        s.add(new_subscriber)
                        try:
                            await s.commit()
                            await s.refresh(new_subscriber)
                            created_subscribers.append(new_subscriber)
                        except IntegrityError:
                            await s.rollback()
                            raise HTTPException(status_code=400, detail="Subscriber already exists")
                return created_subscribers
            if sub_data['type'] == "channel.follow":
                print(f"New follower: {event_data['user_name']}")
        else:
            print("It appears the subdata is empty: {}".format(sub_data))
    return data


# Update an existing subscriber
@app.put('/subcribers/{subscriber_id}', response_model=SubscriberInDB)
async def update_subscriber(subscriber_id: int, subscriber: SubscriberUpdate, session: AsyncSession = Depends(get_session), current_user: str = Depends(get_admin_user)):
    async with session as s:
        existing_subscriber = await s.get(Subscriber, subscriber_id)
        if existing_subscriber is None:
            raise HTTPException(status_code=404, detail="Subscriber not found")
        for key, value in subscriber.dict(exclude_unset=True).items():
            setattr(existing_subscriber, key, value)
        try:
            await s.commit()
        except IntegrityError:
            await s.rollback()
            raise HTTPException(status_code=400, detail="Subscriber already exists...")
        return existing_subscriber


# Delete an existing subscriber
@app.delete('/subscribers/{subscriber_id}', response_model=dict)
async def delete_subscriber(subscriber_id: int, session: AsyncSession = Depends(get_session), current_user: str = Depends(get_admin_user)):
    async with session as s:
        existing_subscriber = await s.get(Subscriber, subscriber_id)
        if existing_subscriber is None:
            raise HTTPException(status_code=404, detail="Subscriber not found")
        await s.delete(existing_subscriber)
        await s.commit()
        return {"subscriber deleted": existing_subscriber.user_name}