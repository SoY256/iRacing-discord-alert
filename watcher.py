import os
import requests

IRACING_EMAIL = os.environ["IRACING_EMAIL"]
IRACING_PASSWORD = os.environ["IRACING_PASSWORD"]
DISCORD_WEBHOOK = os.environ["DISCORD_WEBHOOK_URL"]

session = requests.Session()
session.headers.update({
    "Accept": "application/json",
    "Content-Type": "application/json"
})

def send_discord(msg):
    requests.post(DISCORD_WEBHOOK, json={"content": msg})

def login():
    r = session.post(
        "https://members-ng.iracing.com/auth",
        data={
            "email": IRACING_EMAIL,
            "password": IRACING_PASSWORD
        },
        headers={
            "Content-Type": "application/x-www-form-urlencoded"
        }
    )

    send_discord(f"🔐 Login status: {r.status_code}")

    r.raise_for_status()


    send_discord(f"🔐 Login status: {r.status_code}")

    r.raise_for_status()

def check_hosted():
    send_discord("🚀 Skrypt wystartował")

    login()

    r = session.get("https://members-ng.iracing.com/data/hosted/sessions")
    send_discord(f"📡 Hosted sessions status: {r.status_code}")

    r.raise_for_status()

    data = r.json()
    sessions = data.get("sessions", [])

    send_discord(f"📊 Liczba sesji: {len(sessions)}")

    if not sessions:
        send_discord("❌ Brak sesji w odpowiedzi API")
        return

    for s in sessions[:5]:  # max 5 żeby nie spamować
        msg = (
            "🏁 **HOSTED SESSION**\n\n"
            f"🚗 {s.get('car_name')}\n"
            f"📍 {s.get('track_name')}\n"
            f"🔒 Hasło: {s.get('has_password')}"
        )
        send_discord(msg)

if __name__ == "__main__":
    check_hosted()
