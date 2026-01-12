import os
import requests
import hashlib
import base64
import json

# --- KONFIGURACJA ---
IRACING_EMAIL = os.environ["IRACING_EMAIL"]
IRACING_PASSWORD = os.environ["IRACING_PASSWORD"]
DISCORD_WEBHOOK = os.environ["DISCORD_WEBHOOK_URL"]

session = requests.Session()
session.headers.update({
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "iRacing-Discord-Bot/Test-Mode"
})

def send_discord(msg):
    try:
        requests.post(DISCORD_WEBHOOK, json={"content": msg})
    except Exception as e:
        print(f"❌ Błąd Discord: {e}")

def encode_password(username, password):
    # Szyfrowanie hasła wymagane przez nowe API
    auth_str = (password + username.lower()).encode('utf-8')
    hashed = hashlib.sha256(auth_str).digest()
    return base64.b64encode(hashed).decode('utf-8')

def login():
    print("🔐 Logowanie...")
    payload = {
        "email": IRACING_EMAIL,
        "password": encode_password(IRACING_EMAIL, IRACING_PASSWORD)
    }
    
    r = session.post("https://members-ng.iracing.com/auth", json=payload)
    if r.status_code == 200:
        print("✅ Zalogowano.")
    else:
        print(f"❌ Błąd logowania: {r.status_code} | {r.text}")
        r.raise_for_status()

def check_hosted():
    try:
        login()
    except Exception as e:
        send_discord(f"❌ Błąd krytyczny skryptu (logowanie): {e}")
        return

    print("📡 Pobieranie sesji...")
    r = session.get("https://members-ng.iracing.com/data/hosted/sessions")
    
    if r.status_code != 200:
        send_discord(f"❌ API Error: {r.status_code}")
        return

    data = r.json()
    sessions = data.get("sessions", [])
    
    print(f"📊 Pobrana liczba sesji: {len(sessions)}")
    
    if not sessions:
        send_discord("ℹ️ Lista sesji jest pusta (dziwne, ale możliwe).")
        return

    # WYSYŁAMY 5 PIERWSZYCH SESJI (BEZ FILTROWANIA)
    send_discord(f"🧪 **TEST DZIAŁANIA** - Wyświetlam 5 przykładowych sesji z {len(sessions)} dostępnych:")

    for s in sessions[:5]:
        track = s.get('track', {}).get('track_name', 'Unknown Track')
        session_name = s.get('session_name', 'No Name')
        host = s.get('host', {}).get('display_name', 'Unknown Host')
        is_private = s.get('password_protected', False)
        
        # Wyciągamy nazwy aut
        cars = s.get('cars', [])
        car_names = ", ".join([c.get('car_name', 'Car') for c in cars])
        
        # Skracamy listę aut jeśli długa
        if len(car_names) > 50:
            car_names = car_names[:50] + "..."

        status_icon = "🔒" if is_private else "🔓"

        msg = (
            f"{status_icon} **{session_name}**\n"
            f"📍 {track}\n"
            f"🏎️ {car_names}\n"
            f"👤 Host: {host}\n"
            "-----------------------"
        )
        send_discord(msg)
        print(f"-> Wysłano info o sesji: {session_name}")

if __name__ == "__main__":
    check_hosted()
