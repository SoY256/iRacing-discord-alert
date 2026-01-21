import os
import sys
import requests
import hashlib
import base64
import logging
import json
from datetime import datetime, timezone

# Konfiguracja logowania
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

# --- POBIERANIE ZMIENNYCH ---
CLIENT_ID = os.environ.get("IR_CLIENT_ID", "").strip()
CLIENT_SECRET = os.environ.get("IR_CLIENT_SECRET", "").strip()
EMAIL = os.environ.get("IR_EMAIL", "").strip()
PASSWORD = os.environ.get("IR_PASSWORD", "").strip()
WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK", "").strip()

# Stałe URL
TOKEN_URL = "https://oauth.iracing.com/oauth2/token"
SESSIONS_URL = "https://members-ng.iracing.com/data/hosted/combined_sessions"

def generate_hash(secret, salt):
    if not secret or not salt: return ""
    salt_normalized = salt.strip().lower()
    text_to_hash = secret + salt_normalized
    digest = hashlib.sha256(text_to_hash.encode('utf-8')).digest()
    return base64.b64encode(digest).decode('utf-8')

def get_access_token():
    logger.info("🔐 Logowanie...")
    hashed_password = generate_hash(PASSWORD, EMAIL)
    hashed_client_secret = generate_hash(CLIENT_SECRET, CLIENT_ID)

    payload = {
        "grant_type": "password_limited",
        "username": EMAIL,
        "password": hashed_password,
        "scope": "iracing.auth",
        "client_id": CLIENT_ID,
        "client_secret": hashed_client_secret
    }

    try:
        response = requests.post(TOKEN_URL, data=payload)
        response.raise_for_status()
        return response.json().get("access_token")
    except Exception as e:
        logger.error(f"❌ Błąd logowania: {e}")
        if 'response' in locals(): logger.error(response.text)
        sys.exit(1)

def get_data_from_link(url, token, desc="dane"):
    headers = {"Authorization": f"Bearer {token}"}
    logger.info(f"➡️ Pobieranie: {desc}...")
    try:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()

        if isinstance(data, dict) and 'link' in data:
            s3_resp = requests.get(data['link'])
            s3_resp.raise_for_status()
            return s3_resp.json()
        return data
    except Exception as e:
        logger.error(f"❌ Błąd pobierania {desc}: {e}")
        return None

def get_session_type_name(session):
    """
    Analizuje event_types i session_types, żeby określić charakter sesji.
    Priorytet ma event_type (określa całość).
    """
    # 1. Sprawdzamy Event Type (Nadrzędny typ)
    # 2: Practice, 3: Qualify, 4: Time Trial, 5: Race
    e_types = session.get('event_types', [])
    for e in e_types:
        et = e.get('event_type')
        if et == 5: return "Wyścig"
        if et == 4: return "Time Trial"
        if et == 3: return "Kwalifikacje"
        if et == 2: return "Trening"

    # 2. Jeśli brak event_type, sprawdzamy session_types
    s_types = session.get('session_types', [])
    for s in s_types:
        st = s.get('session_type')
        if st in [5, 6]: return "Wyścig"
        if st in [4, 10]: return "Kwalifikacje"
        if st == 9: return "Rozgrzewka"
    
    return "Trening"

def calculate_remaining_time(session):
    try:
        launch_str = session.get('launch_at')
        if not launch_str: return "Nieznany"
        
        launch_dt = datetime.fromisoformat(launch_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        
        # Obliczamy całkowity czas trwania sesji
        total_minutes = 0
        total_minutes += session.get('practice_length', 0)
        total_minutes += session.get('qualify_length', 0)
        total_minutes += session.get('race_length', 0) 
        
        # Czas, który upłynął
        elapsed = (now - launch_dt).total_seconds() / 60
        remaining = total_minutes - elapsed
        
        if remaining < 0:
            return "W trakcie / Końcówka"
        
        # Formatowanie godziny i minuty
        hours = int(remaining // 60)
        mins = int(remaining % 60)
        
        if hours > 0:
            return f"{hours}h {mins}m"
        else:
            return f"{mins}m"
        
    except Exception:
        return "N/A"

def send_to_discord(sessions):
    if not WEBHOOK_URL: return
    
    # --- FILTROWANIE ---
    # 1. Tylko sesje BEZ hasła
    # 2. Sortowanie (opcjonalne, np. po liczbie graczy)
    public_sessions = [s for s in sessions if s.get('password_protected') is False]
    
    logger.info(f"📨 Znaleziono {len(public_sessions)} publicznych sesji. Wysyłam pierwsze 5...")

    embeds = []
    # Bierzemy pierwsze 5 przefiltrowanych sesji
    for i, s in enumerate(public_sessions[:5], 1):
        name = s.get('session_name', 'Bez nazwy')
        
        # Tor
        track = s.get('track', {}).get('track_name', 'Nieznany tor')
        
        # Host
        host = s.get('host', {}).get('display_name', 'Anonim')
        
        # Typ i Czas
        session_type = get_session_type_name(s)
        time_left = calculate_remaining_time(s)
        
        # Miejsca (num_drivers z Twojego JSONa)
        max_d = s.get('max_drivers', 0)
        curr_d = s.get('num_drivers', 0)
        slots_info = f"{curr_d} / {max_d}"

        # Auta - PROSTO Z JSONA (Klucz "cars")
        cars_list = s.get('cars', [])
        car_names = [c.get('car_name', 'Unknown Car') for c in cars_list]
        
        # Usuwamy duplikaty i sortujemy
        unique_cars = sorted(list(set(car_names)))
        cars_str = ", ".join(unique_cars)
        
        if len(cars_str) > 900: cars_str = cars_str[:897] + "..."
        if not cars_str: cars_str = "Brak danych"

        embed = {
            "title": f"🏎️ {name}",
            "color": 3066993,
            "fields": [
                {"name": "📍 Tor", "value": track, "inline": True},
                {"name": "👤 Host", "value": host, "inline": True},
                {"name": "⏳ Czas", "value": time_left, "inline": True},
                {"name": "🏁 Typ", "value": session_type, "inline": True},
                {"name": "👥 Miejsca", "value": slots_info, "inline": True},
                {"name": "🚗 Auta", "value": cars_str, "inline": False}
            ],
            "footer": {"text": f"ID Sesji: {s.get('session_id', 'N/A')}"}
        }
        embeds.append(embed)

    if embeds:
        try:
            requests.post(WEBHOOK_URL, json={"embeds": embeds})
            logger.info("✅ Powiadomienie wysłane!")
        except Exception as e:
            logger.error(f"❌ Błąd Discorda: {e}")
    else:
        logger.info("ℹ️ Brak sesji spełniających kryteria (brak hasła).")

def main():
    token = get_access_token()
    
    # Nie potrzebujemy już pobierać słowników aut/klas!
    # Wszystko jest w głównym zapytaniu.
    
    data = get_data_from_link(SESSIONS_URL, token, "Lista Sesji")
    if not data: sys.exit(1)

    sessions = data.get('sessions', [])
    logger.info(f"📊 Pobrano łącznie {len(sessions)} sesji (surowe dane).")
    
    if sessions:
        send_to_discord(sessions)
    else:
        logger.info("ℹ️ Pusta lista sesji.")

if __name__ == "__main__":
    main()
