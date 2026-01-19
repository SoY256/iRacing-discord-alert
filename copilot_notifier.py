import os
import requests
from datetime import datetime

# Pobieranie danych z ENV (ustawionych jako sekrety GitHub)
IRACING_USERNAME = os.getenv("IR_EMAIL")
IRACING_PASSWORD = os.getenv("IR_PASSWORD")
CLIENT_ID = os.getenv("IR_CLIENT_ID")
CLIENT_SECRET = os.getenv("IR_CLIENT_SECRET")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK")

TOKEN_URL = "https://oauth.iracing.com/oauth2/token"
HOSTED_SESSIONS_URL = "https://members-ng.iracing.com/data/hosted/sessions"

def get_access_token():
    payload = {
        "grant_type": "password",
        "username": IRACING_USERNAME,
        "password": IRACING_PASSWORD,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "data:read"
    }
    response = requests.post(TOKEN_URL, data=payload)
    response.raise_for_status()
    return response.json()["access_token"]

def get_hosted_sessions(token):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(HOSTED_SESSIONS_URL, headers=headers)
    response.raise_for_status()
    link = response.json().get("link")
    if not link:
        return []
    data_response = requests.get(link)
    data_response.raise_for_status()
    return data_response.json()

def send_to_discord(sessions):
    embeds = []
    for s in sessions[:5]:
        start_time = datetime.fromtimestamp(s["launch_at"]).strftime("%Y-%m-%d %H:%M")
        embed = {
            "title": s.get("session_name", "Brak nazwy"),
            "color": 0x00ff99,
            "fields": [
                {"name": "Tor", "value": s.get("track", "Nieznany"), "inline": True},
                {"name": "Samochody", "value": ", ".join(s.get("cars", [])), "inline": True},
                {"name": "Start", "value": start_time, "inline": False},
            ]
        }
        embeds.append(embed)
    requests.post(DISCORD_WEBHOOK_URL, json={"embeds": embeds})

def main():
    print("🔐 Autoryzacja...")
    token = get_access_token()
    print("📡 Pobieranie sesji...")
    sessions = get_hosted_sessions(token)
    if not sessions:
        print("Brak aktywnych sesji.")
        return
    print("📨 Wysyłanie na Discord...")
    send_to_discord(sessions)
    print("✅ Gotowe!")

if __name__ == "__main__":
    main()
