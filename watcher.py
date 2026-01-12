import os
import requests

IRACING_EMAIL = os.environ["IRACING_EMAIL"]
IRACING_PASSWORD = os.environ["IRACING_PASSWORD"]
DISCORD_WEBHOOK = os.environ["DISCORD_WEBHOOK_URL"]

CAR_NAME = "Dallara iR-01"
TRACK_NAME = "Spa-Francorchamps"

session = requests.Session()

def login():
    session.post(
        "https://members-ng.iracing.com/auth",
        json={"email": IRACING_EMAIL, "password": IRACING_PASSWORD},
    )

def send_discord(msg):
    requests.post(
        DISCORD_WEBHOOK,
        json={"content": msg}
    )

def check_hosted():
    login()
    r = session.get("https://members-ng.iracing.com/data/hosted/sessions")
    sessions = r.json()["sessions"]

    for s in sessions:
        if s["has_password"]:
            continue
        if CAR_NAME not in s["Dallara F3"]:
            continue
        if TRACK_NAME not in s["Lime Rock Park"]:
            continue

        msg = (
            "🏁 **NOWA HOSTED SESSION!**\n\n"
            f"🚗 **{s['car_name']}**\n"
            f"📍 **{s['track_name']}**\n"
            "🔓 Publiczna (bez hasła)"
        )
        send_discord(msg)

if __name__ == "__main__":
    check_hosted()
