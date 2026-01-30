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

# --- NAPRAWIONE FILTRY ---
# 1. Pobieramy z env
env_tracks = os.environ.get("FILTER_TRACKS", "").strip()
env_cars = os.environ.get("FILTER_CARS", "").strip()

# 2. Jeśli env jest pusty, używamy Twoich domyślnych wartości HARDCODED
# WPISZ SWOJE DOMYŚLNE WARTOŚCI TUTAJ, JEŚLI CHCESZ:
DEFAULT_TRACKS = "Spa,Monza,Charlotte,Navarra,Barcelona,Daytona,Oran,oulton,Miami International,Tsukuba,Winton,WeatherTech,Virginia International"
DEFAULT_CARS = "W12,W13,SF23,DW12,MP4,iR-01,IL-15,F3,F4,Super Formula Lights"  #Porsche 911 GT3 R (992)

# Logika: Użyj Env, a jak pusty to Default
final_tracks_str = env_tracks if env_tracks else DEFAULT_TRACKS
final_cars_str = env_cars if env_cars else DEFAULT_CARS

# Tworzenie list
FILTER_TRACKS = [x.strip().lower() for x in final_tracks_str.split(',') if x.strip()]
FILTER_CARS = [x.strip().lower() for x in final_cars_str.split(',') if x.strip()]

# Stałe
TOKEN_URL = "https://oauth.iracing.com/oauth2/token"
SESSIONS_URL = "https://members-ng.iracing.com/data/hosted/combined_sessions"
HISTORY_FILE = "seen_sessions.json"

def ensure_history_file_exists():
    if not os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'w') as f:
                json.dump([], f)
            logger.info(f"🆕 Utworzono pusty plik historii: {HISTORY_FILE}")
        except Exception as e:
            logger.error(f"❌ Błąd tworzenia pliku: {e}")

def load_seen_sessions():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                return set(json.load(f))
        except Exception as e:
            logger.warning(f"⚠️ Błąd odczytu historii: {e}")
    return set()

def save_seen_sessions(seen_ids):
    try:
        limited_list = sorted(list(seen_ids))[-2000:] 
        with open(HISTORY_FILE, 'w') as f:
            json.dump(limited_list, f, indent=2)
        logger.info(f"💾 Zapisano historię ({len(limited_list)} sesji).")
    except Exception as e:
        logger.error(f"❌ Błąd zapisu historii: {e}")

def generate_hash(secret, salt):
    if not secret or not salt: return ""
    salt_normalized = salt.strip().lower()
    text_to_hash = secret + salt_normalized
    digest = hashlib.sha256(text_to_hash.encode('utf-8')).digest()
    return base64.b64encode(digest).decode('utf-8')

def get_access_token():
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
        sys.exit(1)

def get_data_from_link(url, token, desc="dane"):
    headers = {"Authorization": f"Bearer {token}"}
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
    except Exception: return "N/A"

def check_filters(session):
    # Logika: Jeśli lista filtrów jest PUSTA, zwracamy True (pokaż wszystko).
    # Ale teraz upewniliśmy się na początku pliku, że jeśli chcesz Porsche, to lista nie jest pusta.

    # 1. TOR
    if FILTER_TRACKS:
        track_name = session.get('track', {}).get('track_name', '').lower()
        if not any(f in track_name for f in FILTER_TRACKS): return False

    # 2. AUTO
    if FILTER_CARS:
        session_cars = session.get('cars', [])
        session_car_names = [c.get('car_name', '').lower() for c in session_cars]
        
        match_car = False
        for s_car in session_car_names:
            for f_car in FILTER_CARS:
                # Sprawdzamy czy fraza (np. "porsche") jest w nazwie auta (np. "porsche 911 gt3")
                if f_car in s_car:
                    match_car = True
                    break
            if match_car: break
        
        if not match_car: return False
        
    return True

def is_session_valid(s):
    if s.get('password_protected') is True: return False
    
    reg_expires_str = s.get('open_reg_expires')
    if reg_expires_str:
        try:
            reg_dt = datetime.fromisoformat(reg_expires_str.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if now > reg_dt: return False
        except ValueError: pass

    if not check_filters(s): return False
    return True

def send_to_discord(sessions, seen_ids):
    if not WEBHOOK_URL: return set()
    
    # Najpierw filtrujemy merytorycznie
    valid_sessions = [s for s in sessions if is_session_valid(s)]
    
    # Potem sprawdzamy duplikaty
    new_sessions = []
    for s in valid_sessions:
        sid = s.get('session_id')
        if sid and sid not in seen_ids:
            new_sessions.append(s)
    
    logger.info(f"🧐 Statystyki: Wszystkie={len(sessions)} | Zgodne z filtrem={len(valid_sessions)} | NOWE={len(new_sessions)}")
    
    if not new_sessions:
        return set()

    all_embeds = []
    ids_to_add = set()

    for i, s in enumerate(new_sessions, 1):
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
        if s.get('session_id'):
            ids_to_add.add(s.get('session_id'))

    batch_size = 10
    total_sent = 0
    for i in range(0, len(all_embeds), batch_size):
        batch = all_embeds[i : i + batch_size]
        try:
            requests.post(WEBHOOK_URL, json={"embeds": batch})
            total_sent += len(batch)
            time.sleep(1)
        except Exception as e:
            logger.error(f"❌ Błąd Discorda: {e}")

    logger.info(f"✅ Wysłano {total_sent} nowych powiadomień.")
    return ids_to_add

def main():
    # 1. LOGOWANIE FILTRÓW (Bardzo ważne dla Ciebie)
    print("="*40)
    print(f"DEBUG: Pobrany string filtrów torów (ENV): '{env_tracks}'")
    print(f"DEBUG: Pobrany string filtrów aut (ENV):   '{env_cars}'")
    print(f"🔧 AKTYWNE FILTRY TORÓW: {FILTER_TRACKS}")
    print(f"🔧 AKTYWNE FILTRY AUT:   {FILTER_CARS}")
    print("="*40)

    ensure_history_file_exists()

    token = get_access_token()
    seen_ids = load_seen_sessions()
    logger.info(f"📂 Wczytano historię: {len(seen_ids)} znanych sesji.")

    data = get_data_from_link(SESSIONS_URL, token, "Lista Sesji")
    if not data: sys.exit(1)

    sessions = data.get('sessions', [])
    newly_sent_ids = send_to_discord(sessions, seen_ids)
    
    if newly_sent_ids:
        updated_seen_ids = seen_ids.union(newly_sent_ids)
        save_seen_sessions(updated_seen_ids)
    else:
        logger.info("💤 Brak nowych sesji. Zapisuję stan.")
        save_seen_sessions(seen_ids)

if __name__ == "__main__":
    main()
