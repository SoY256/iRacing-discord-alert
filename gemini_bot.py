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
CARS_ASSETS_URL = "https://members-ng.iracing.com/data/car/get"
CLASSES_ASSETS_URL = "https://members-ng.iracing.com/data/carclass/get"

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

def get_dictionaries(token):
    # 1. Auta
    raw_cars = get_data_from_link(CARS_ASSETS_URL, token, "Słownik Aut")
    car_map = {}
    if raw_cars:
        for c in raw_cars:
            if 'car_id' in c and 'car_name' in c:
                car_map[str(c['car_id'])] = c['car_name']
    
    # 2. Klasy
    raw_classes = get_data_from_link(CLASSES_ASSETS_URL, token, "Słownik Klas")
    class_map = {}
    if raw_classes:
        for cls in raw_classes:
            cars_ids = [c['car_id'] for c in cls.get('cars_in_class', []) if 'car_id' in c]
            if 'short_name' in cls and cls['short_name']:
                class_map[cls['short_name'].lower().strip()] = cars_ids
            if 'name' in cls and cls['name']:
                class_map[cls['name'].lower().strip().replace(" ", "")] = cars_ids

    return car_map, class_map

def resolve_cars_clean(session, car_map, class_map):
    concrete_cars = set()
    entries = session.get('car_types', []) + session.get('cars', [])
    if not entries: entries = session.get('car_classes', [])

    for entry in entries:
        c_id = None
        type_str = None

        if isinstance(entry, dict):
            c_id = entry.get('car_id') or entry.get('id')
            type_str = entry.get('car_type') or entry.get('car_class_short_name')
        elif isinstance(entry, int):
            c_id = entry
        elif isinstance(entry, str):
            type_str = entry

        if c_id is not None and str(c_id) in car_map:
            concrete_cars.add(car_map[str(c_id)])
            continue

        if type_str:
            clean_type = str(type_str).lower().strip().replace(" ", "")
            if clean_type in class_map:
                for car_id in class_map[clean_type]:
                    if str(car_id) in car_map:
                        concrete_cars.add(car_map[str(car_id)])

    if not concrete_cars:
        return ["Nieznane (Brak danych)"]

    return sorted(list(concrete_cars))

def get_session_type(session):
    st_list = session.get('session_types', [])
    types_found = []
    
    # Mapa ID -> Nazwa
    type_map = {
        0: "Trening", 
        1: "Kwalifikacje",
        2: "Kwalifikacje", # Czasem lone qualify
        3: "Trening", # Lone Practice
        4: "Kwalifikacje", # Open Qualify
        5: "Wyścig",
        6: "Wyścig",
        9: "Rozgrzewka",
        10: "Kwalifikacje"
    }
    
    for item in st_list:
        sid = -1
        if isinstance(item, dict):
            sid = item.get('session_type')
        elif isinstance(item, int):
            sid = item
            
        if sid is not None:
            name = type_map.get(sid, "Sesja")
            if name not in types_found:
                types_found.append(name)
            
    # Unikalne, zachowując kolejność
    seen = set()
    unique = [x for x in types_found if not (x in seen or seen.add(x))]
    return ", ".join(unique) if unique else "Trening"

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
        
        if remaining < 0:
            return "W trakcie / Końcówka"
        
        # --- NOWY FORMAT CZASU (1h 25m) ---
        hours = int(remaining // 60)
        mins = int(remaining % 60)
        
        if hours > 0:
            return f"{hours}h {mins}m"
        else:
            return f"{mins}m"
        
    except Exception:
        return "N/A"

def send_to_discord(sessions, car_map, class_map):
    if not WEBHOOK_URL: return
    logger.info(f"📨 Wysyłanie {len(sessions)} sesji na Discorda...")

    embeds = []
    for i, s in enumerate(sessions, 1):
        name = s.get('session_name', 'Bez nazwy')
        
        # Celowany Debug dla konkretnej sesji
        if "Adelaide" in name:
            logger.info(f"🔍🔍🔍 DEBUG DLA SESJI: {name}")
            logger.info("Zrzucam pełną strukturę JSON, żeby znaleźć kierowców:")
            logger.info(json.dumps(s, indent=2))
            logger.info("🔍🔍🔍 KONIEC ZRZUTU")

        track_data = s.get('track', {})
        if isinstance(track_data, dict):
            track = track_data.get('track_name', 'Nieznany tor')
        else:
            track = "Nieznany tor (ID)"
            
        host_data = s.get('host', {})
        host = host_data.get('display_name', 'Anonim') if isinstance(host_data, dict) else "Anonim"
        
        session_type = get_session_type(s)
        time_left = calculate_remaining_time(s)
        
        max_d = s.get('max_drivers', 0)
        reg_d = s.get('num_registered', 0)
        slots_info = f"{reg_d} / {max_d}"

        car_names_list = resolve_cars_clean(s, car_map, class_map)
        cars_str = ", ".join(car_names_list)
        if len(cars_str) > 900: cars_str = cars_str[:897] + "..."

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

    try:
        requests.post(WEBHOOK_URL, json={"embeds": embeds})
        logger.info("✅ Powiadomienie wysłane!")
    except Exception as e:
        logger.error(f"❌ Błąd Discorda: {e}")

def main():
    token = get_access_token()
    car_map, class_map = get_dictionaries(token)
    
    data = get_data_from_link(SESSIONS_URL, token, "Lista Sesji")
    if not data: sys.exit(1)

    sessions = data.get('sessions', [])
    logger.info(f"📊 Znaleziono łącznie {len(sessions)} sesji.")
    
    top_5 = sessions[:5]
    if top_5:
        send_to_discord(top_5, car_map, class_map)
    else:
        logger.info("ℹ️ Brak sesji.")

if __name__ == "__main__":
    main()
