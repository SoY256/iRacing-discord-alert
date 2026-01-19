import os
import base64
import hashlib
import requests
from datetime import datetime

TOKEN_URL = "https://oauth.iracing.com/oauth2/token"
HOSTED_URL = "https://data.iracing.com/data/hosted/hosted_sessions"

def mask_value(secret: str, identifier: str) -> str:
    """
    Masking algorithm exactly as specified in iRacing OAuth docs:
    SHA256(secret + lowercase(trim(identifier))) -> standard Base64
    """
    normal_id = identifier.strip().lower()
    combined = (secret + normal_id).encode("utf-8")
    digest = hashlib.sha256(combined).digest()
    return base64.b64encode(digest).decode("utf-8")

def get_access_token() -> str:
    client_id = os.environ["IR_CLIENT_ID"]
    client_secret = os.environ["IR_CLIENT_SECRET"]
    email = os.environ["IR_EMAIL"]
    password = os.environ["IR_PASSWORD"]

    # Mask client_secret and password
    masked_client_secret = mask_value(client_secret, client_id)
    masked_password = mask_value(password, email)

    # Prepare body
    payload = {
        "grant_type": "password_limited",
        "client_id": client_id,
        "client_secret": masked_client_secret,
        "username": email,
        "password": masked_password,
        "scope": "iracing.auth"
    }

    response = requests.post(TOKEN_URL, data=payload, headers={
        "Content-Type": "application/x-www-form-urlencoded"
    }, timeout=15)

    if response.status_code != 200:
        raise RuntimeError(f"Token error {response.status_code}: {response.text}")

    return response.json()["access_token"]

def get_hosted_sessions(token: str) -> list:
    response = requests.get(
        HOSTED_URL,
        headers={"Authorization": f"Bearer {token}"},
        timeout=15
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
