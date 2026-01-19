import os
import hashlib
import requests
from datetime import datetime
import base64

TOKEN_URL = "https://oauth.iracing.com/oauth2/token"
HOSTED_URL = "https://data.iracing.com/data/hosted/hosted_sessions"

def mask_password(password: str, email: str) -> str:
    """
    iRacing Password Limited Flow password mask:
    SHA256(password + lowercase(trim(email))) -> base64 without URL-safe issues
    """
    concat = (password + email.strip().lower()).encode("utf-8")
    digest = hashlib.sha256(concat).digest()
    # standard Base64, remove padding
    return base64.b64encode(digest).decode("utf-8").rstrip("=")

def get_access_token() -> str:
    client_id = os.environ["IR_CLIENT_ID"]
    client_secret = os.environ["IR_CLIENT_SECRET"]
    email = os.environ["IR_EMAIL"]
    password = os.environ["IR_PASSWORD"]

    # Basic Auth: standard Base64 client_id:client_secret
    basic_auth = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("utf-8")

    headers = {
        "Authorization": f"Basic {basic_auth}",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    payload = {
        "grant_type": "password_limited",
        "client_id": client_id,
        "client_secret": client_secret,
        "username": email,
        "password": mask_password(password, email),
        "audience": "data-server",
    }

    response = requests.post(TOKEN_URL, headers=headers, data=payload, timeout=15)

    if response.status_code != 200:
        raise RuntimeError(f"Token error {response.status_code}: {response.text}")

    return response.json()["access_token"]

def get_hosted_sessions(token: str) -> list:
    response = requests.get(
        HOSTED_URL,
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )

    if response.status_code != 200:
        raise RuntimeError(f"Hosted sessions error {response.status_code}: {response.text}")

    return response.json().get("sessions", [])

def format_sessions(sessions: list) -> str:
    lines = []
    for s in sessions[:5]:
        start = datetime.fromisoformat(s["start_time"].replace("Z", ""))
        lines.append(
            f"**{s['session_name']}**\n"
            f"Track: {s['track']['track_name']}\n"
            f"Car: {s['car_class']['short_name']}\n"
            f"Start: {start:%Y-%m-%d %H:%M UTC}\n"
        )
    return "\n".join(lines)

def send_to_discord(message: str) -> None:
    webhook = os.environ["DISCORD_WEBHOOK"]
    response = requests.post(webhook, json={"content": f"🏁 **iRacing Hosted Sessions** 🏁\n\n{message}"}, timeout=15)
    if response.status_code not in (200, 204):
        raise RuntimeError(f"Discord webhook error {response.status_code}: {response.text}")

def main() -> None:
    print("🔐 Getting access token...")
    token = get_access_token()

    print("📡 Fetching hosted sessions...")
    sessions = get_hosted_sessions(token)

    if not sessions:
        send_to_discord("No hosted sessions available right now.")
        print("ℹ️ No sessions found")
        return

    send_to_discord(format_sessions(sessions))
    print("✅ Notification sent")

if __name__ == "__main__":
    main()
