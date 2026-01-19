import os
import base64
import hashlib
import requests
from datetime import datetime

TOKEN_URL = "https://oauth.iracing.com/oauth2/token"
HOSTED_URL = "https://data.iracing.com/data/hosted/hosted_sessions"


def mask_password(password: str, email: str) -> str:
    raw = (password + email.strip().lower()).encode("utf-8")
    digest = hashlib.sha256(raw).digest()
    return base64.b64encode(digest).decode("utf-8")


def get_access_token() -> str:
    client_id = os.environ["IR_CLIENT_ID"]
    client_secret = os.environ["IR_CLIENT_SECRET"]
    email = os.environ["IR_EMAIL"]
    password = os.environ["IR_PASSWORD"]

    basic_auth = base64.b64encode(
        f"{client_id}:{client_secret}".encode("utf-8")
    ).decode("utf-8")

    headers = {
        "Authorization": f"Basic {basic_auth}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    payload = {
        "grant_type": "password_limited",
        "client_id": client_id,
        "client_secret": client_secret,
        "username": email,
        "password": mask_password(password, email),
        "audience": "data-server"
    }

    response = requests.post(
        TOKEN_URL,
        headers=headers,
        data=payload,
        timeout=15
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Token error {response.status_code}: {response.text}"
        )

    return response.json()["access_token"]


def get_hosted_sessions(token: str) -> list:
    response = requests.get(
        HOSTED_URL,
        headers={"Authorization": f"Bearer {token}"},
        timeout=15
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Hosted sessions error {response.status_code}: {response.text}"
        )

    return response.json().get("sessions", [])


def format_sessions(sessions: list) -> str:
