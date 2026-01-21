import os
import sys
import requests
import hashlib
import base64
import logging
import json

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
    """Buduje mapy aut i klas."""
    # 1. Auta
    raw_cars = get_data_from_link(CARS_ASSETS_URL, token, "Słownik Aut")
    car_map = {} # ID -> Nazwa
    
    if raw_cars:
        for c in raw_cars:
            if 'car_id' in c and 'car_name' in c:
                car_map[c['car_id']] = c['car_name']
                car_map[str(c['car_id'])] = c['car_name'] # String version
    
    # 2. Klasy (Tylko ścisłe dopasowanie!)
    raw_classes = get_data_from_link(CLASSES_ASSETS_URL, token, "Słownik Klas")
    class_map = {} 
    
    if raw_classes:
        for cls in raw_classes:
            # Używamy short_name (np. "gt3") i name (np. "IMSA GT3") jako kluczy
            # Ale bez spacji i lowercase
            cars_ids = [c['car_id'] for c in cls.get('cars_in_class', []) if 'car_id' in c]
            
            if 'short_name' in cls and cls['short_name']:
                k = cls['short_name'].lower().strip()
                class_map[k] = cars_ids
            
            if 'name' in cls and cls['name']:
                k = cls['name'].lower().strip().replace(" ", "")
                class_map[k] = cars_ids

    return car_map, class_map

def resolve_cars_strict(session, car_map, class_map):
    """
    Logika ŚCISŁA (Strict): Żadnego zgadywania. 
    Albo mamy ID, albo dokładną nazwę klasy.
    """
    resolved_car_names = set()
    
    # Pobieramy wszystko co może być autem
    entries = session.get('car_types', []) + session.get('cars', [])
    
    # Jeśli lista jest pusta, sprawdźmy car_classes (rzadki przypadek)
    if not entries:
        entries = session.get('car_classes', [])

    for entry in entries:
        c_id = None
        type_str = None

        # Rozpoznawanie typu danych
        if isinstance(entry, dict):
            c_id = entry.get('car_id') or entry.get('id')
            type_str = entry.get('car_type') or entry.get('car_class_short_name')
        elif isinstance(entry, int):
            c_id = entry
        elif isinstance(entry, str):
            type_str = entry

        # 1. Mamy konkretne ID -> Zamieniamy na nazwę
        if c_id is not None:
            if str(c_id) in car_map:
                resolved_car_names.add(car_map[str(c_id)])
            else:
                resolved_car_names.add(f"Car #{c_id}")
            continue

        # 2. Mamy nazwę typu/klasy (np. "gt3", "ff1600")
        if type_str:
            clean_type = str(type_str).lower().strip().replace(" ", "")
            
            # Sprawdzamy czy to KLASA (np. GT3)
            if clean_type in class_map:
                # Rozpakowujemy klasę na auta
                for car_id in class_map[clean_type]:
                    if str(car_id) in car_map:
                        resolved_car_names.add(car_map[str(car_id)])
            else:
                # Jeśli to nie klasa, to może to kod konkretnego auta? (np. "ff1600")
                # Próbujemy znaleźć auto, którego nazwa zawiera ten kod (bezpieczniejsze niż zgadywanie klasy)
                found_match = False
                
                # Szybkie szukanie "Reverse Search"
                # Jeśli kod to "ff1600", a w bazie jest "Ray FF1600", to dopasuj.
                # Ale tylko jeśli jest BARDZO podobne.
                for cid, cname in car_map.items():
                    if clean_type == "ff1600" and "FF1600" in cname:
                        resolved_car_names.add(cname)
                        found_match = True
                        break
                
                if not found_match:
                    # Jeśli nadal nie wiemy co to, wypisz surowy kod.
                    # LEPIEJ WYPISAĆ "[Typ: xyz]" NIŻ KŁAMAĆ.
                    resolved_car_names.add(f"[{str(type_str).capitalize()}]")

    if not resolved_car_names:
        return ["Brak danych"]

    return sorted(list(resolved_car_names))

def send_to_discord(sessions, car_map, class_map):
    if not WEBHOOK_URL: return
    logger.info(f"📨 Wysyłanie {len(sessions)} sesji na Discorda...")

    embeds = []
    for i, s in enumerate(sessions, 1):
        name = s.get('session_name', 'Bez nazwy')
        track = s.get('track', {}).get('track_name', 'Nieznany tor')
        host = s.get('host', {}).get('display_name', 'Anonim')
        
        # Używamy nowej, ścisłej logiki
        car_names_list = resolve_cars_strict(s, car_map, class_map)
        
        cars_str = ", ".join(car_names_list)
        
        if len(cars_str) > 1000: 
            cars_str = cars_str[:997] + "..."

        embed = {
            "title": f"🏎️ Sesja: {name}",
            "color": 3066993,
            "fields": [
                {"name": "📍 Tor", "value": track, "inline": True},
                {"name": "👤 Host", "value": host, "inline": True},
                {"name": "🚗 Auta", "value": cars_str, "inline": False}
            ],
            "footer": {"text": f"ID: {s.get('session_id', 'N/A')}"}
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
