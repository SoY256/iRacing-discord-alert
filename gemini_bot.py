import os
import sys
import requests
import hashlib
import base64
import logging
import json
import time
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

# --- ZMIENNE FILTRUJĄCE ---
FILTER_TRACKS_STR = os.environ.get("FILTER_TRACKS", "bull, silver")
FILTER_CARS_STR = os.environ.get("FILTER_CARS", "vee,porsche")

FILTER_TRACKS = [x.strip().lower() for x in FILTER_TRACKS_STR.split(',') if x.strip()]
FILTER_CARS = [x.strip().lower() for x in FILTER_CARS_STR.split(',') if x.strip()]

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
    e_types = session.get('event_types', [])
    for e in e_types:
        et = e.get('event_type')
        if et == 5: return "Wyścig"
        if et == 4: return "Time Trial"
        if et == 3: return "Kwalifikacje"
        if et == 2: return "Trening"

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
        total_minutes = 0
        total_minutes += session.get('practice_length', 0)
        total_minutes += session.get('qualify_length', 0)
        total_minutes += session.get('race_length', 0) 
        elapsed = (now - launch_dt).total_seconds() / 60
        remaining = total_minutes - elapsed
        
        if remaining < 0: return "W trakcie / Końcówka"
        
        hours = int(remaining // 60)
        mins = int(remaining % 60)
        if hours > 0: return f"{hours}h {mins}m"
        else: return f"{mins}m"
    except Exception:
        return "N/A"

def check_filters(session):
    # 1. FILTR TORÓW
    if FILTER_TRACKS:
        track_name = session.get('track', {}).get('track_name', '').lower()
        match_track = any(f in track_name for f in FILTER_TRACKS)
        if not match_track:
            return False

    # 2. FILTR AUT
    if FILTER_CARS:
        session_cars = session.get('cars', [])
        session_car_names = [c.get('car_name', '').lower() for c in session_cars]
        match_car = False
        for s_car in session_car_names:
            for f_car in FILTER_CARS:
                if f_car in s_car:
                    match_car = True
                    break
            if match_car: break
        
        if not match_car:
            return False

    return True

def is_session_valid(s):
    # 1. Hasło
    if s.get('password_protected') is True: return False

    # 2. Status rejestracji ("Closed")
    reg_expires_str = s.get('open_reg_expires')
    if reg_expires_str:
        try:
            reg_dt = datetime.fromisoformat(reg_expires_str.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if now > reg_dt: return False
        except ValueError: pass

    # 3. FILTRY UŻYTKOWNIKA
    if not check_filters(s): return False

    return True

def send_to_discord(sessions):
    if not WEBHOOK_URL: return
    
    # Filtrowanie sesji
    valid_sessions = [s for s in sessions if is_session_valid(s)]
    
    logger.info(f"🧐 Filtrowanie: Pobranno {len(sessions)}. Pasuje: {len(valid_sessions)} sesji.")
    
    if not valid_sessions:
        logger.info("ℹ️ Brak sesji spełniających kryteria.")
        return

    # Budowanie listy wszystkich embedów
    all_embeds = []
    
    # Iterujemy przez WSZYSTKIE pasujące sesje (bez limitu [:5])
    for i, s in enumerate(valid_sessions, 1):
        name = s.get('session_name', 'Bez nazwy')
        track = s.get('track', {}).get('track_name', 'Nieznany tor')
        host = s.get('host', {}).get('display_name', 'Anonim')
        session_type = get_session_type_name(s)
        time_left = calculate_remaining_time(s)
        
        max_d = s.get('max_drivers', 0)
        curr_d = s.get('num_drivers', 0)
        slots_info = f"{curr_d} / {max_d}"

        cars_list = s.get('cars', [])
        car_names = [c.get('car_name', 'Unknown Car') for c in cars_list]
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
        all_embeds.append(embed)

    # --- MECHANIZM PACZKOWANIA (Batching) ---
    # Discord przyjmuje max 10 embedów na raz.
    # Dzielimy listę 'all_embeds' na kawałki po 10 elementów.
    
    batch_size = 10
    total_sent = 0
    
    for i in range(0, len(all_embeds), batch_size):
        batch = all_embeds[i : i + batch_size]
        
        try:
            logger.info(f"📨 Wysyłanie paczki {i//batch_size + 1} ({len(batch)} sesji)...")
            requests.post(WEBHOOK_URL, json={"embeds": batch})
            total_sent += len(batch)
            
            # Ważne: Mała pauza, żeby Discord nie zablokował webhooka za spam
            time.sleep(1) 
            
        except Exception as e:
            logger.error(f"❌ Błąd Discorda przy paczce {i}: {e}")

    logger.info(f"✅ Zakończono wysyłanie. Wysłano łącznie: {total_sent} sesji.")

def main():
    token = get_access_token()
    
    if FILTER_TRACKS: logger.info(f"🔍 Filtr Torów AKTYWNY: {FILTER_TRACKS}")
    else: logger.info("🔍 Filtr Torów: WYŁĄCZONY")
    
    if FILTER_CARS: logger.info(f"🔍 Filtr Aut AKTYWNY: {FILTER_CARS}")
    else: logger.info("🔍 Filtr Aut: WYŁĄCZONY")

    data = get_data_from_link(SESSIONS_URL, token, "Lista Sesji")
    if not data: sys.exit(1)

    sessions = data.get('sessions', [])
    if sessions:
        send_to_discord(sessions)
    else:
        logger.info("ℹ️ Pusta lista sesji.")

if __name__ == "__main__":
    main()
