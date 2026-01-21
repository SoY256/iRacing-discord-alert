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
CARS_ASSETS_URL = "https://members-ng.iracing.com/data/car/get"      # Słownik Aut
CLASSES_ASSETS_URL = "https://members-ng.iracing.com/data/carclass/get" # Słownik Klas (NOWOŚĆ)

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
    """
    Pobiera i buduje dwie mapy:
    1. car_map: ID Auta -> Nazwa Auta (np. 145 -> "Ferrari 296 GT3")
    2. class_map: Nazwa Klasy (lowercase) -> Lista ID Aut (np. "gt3" -> [145, 146...])
    """
    # 1. Pobieranie Aut
    raw_cars = get_data_from_link(CARS_ASSETS_URL, token, "Słownik Aut")
    car_map = {}
    if raw_cars:
        for c in raw_cars:
            if 'car_id' in c and 'car_name' in c:
                car_map[c['car_id']] = c['car_name']
    
    # 2. Pobieranie Klas (To jest klucz do rozwiązania Twojego problemu)
    raw_classes = get_data_from_link(CLASSES_ASSETS_URL, token, "Słownik Klas")
    class_map = {} # Klucz: nazwa klasy (lower), Wartość: lista ID aut
    
    if raw_classes:
        for cls in raw_classes:
            # Nazwa klasy, np. "GT3 Class"
            cls_name = cls.get('name', '').lower()
            cls_short = cls.get('short_name', '').lower()
            
            # Wyciągamy listę ID aut w tej klasie
            cars_in_class = [c['car_id'] for c in cls.get('cars_in_class', []) if 'car_id' in c]
            
            # Mapujemy zarówno pełną nazwę jak i skróconą
            if cls_name: class_map[cls_name] = cars_in_class
            if cls_short: class_map[cls_short] = cars_in_class
            
            # Czasem iRacing używa nazw typu "gt3" jako klucza, więc usuwamy spacje dla pewności
            if cls_name: class_map[cls_name.replace(" ", "")] = cars_in_class

    logger.info(f"📚 Zbudowano słowniki: {len(car_map)} aut, {len(class_map)} klas.")
    return car_map, class_map

def resolve_cars_for_session(session, car_map, class_map):
    """Inteligentne tłumaczenie zawartości sesji na listę konkretnych aut."""
    resolved_car_names = set()
    
    # Pobieramy surowe dane o autach/klasach z sesji
    # Mogą być w: car_types (napisy), cars (obiekty), car_classes (obiekty)
    entries = session.get('car_types', []) + session.get('cars', []) + session.get('car_classes', [])
    
    for entry in entries:
        # Przypadek 1: Mamy konkretne ID auta (car_id)
        c_id = None
        if isinstance(entry, dict):
            c_id = entry.get('car_id') or entry.get('id')
        elif isinstance(entry, int):
            c_id = entry
            
        if c_id and c_id in car_map:
            resolved_car_names.add(car_map[c_id])
            continue

        # Przypadek 2: Mamy nazwę klasy/typu (np. "gt3", "aussiev8")
        type_str = ""
        if isinstance(entry, dict):
            type_str = entry.get('car_type') or entry.get('name') or entry.get('car_class_short_name')
        elif isinstance(entry, str):
            type_str = entry
            
        if type_str:
            type_key = str(type_str).lower().strip().replace(" ", "")
            
            # Szukamy tej nazwy w naszej mapie klas
            # Przeszukujemy klucze mapy, sprawdzając czy 'type_key' jest częścią nazwy klasy
            # np. jeśli sesja ma "gt3", a my mamy klasę "imsa gt3", to może być match
            
            found_class_cars = []
            
            # Dokładne dopasowanie
            if type_key in class_map:
                found_class_cars = class_map[type_key]
            else:
                # Luźne dopasowanie (jeśli "gt3" jest w nazwie klasy)
                for k, v in class_map.items():
                    if type_key == k or (len(type_key) > 2 and type_key in k):
                        found_class_cars.extend(v)
            
            if found_class_cars:
                # Zamieniamy znalezione ID aut na ich nazwy
                for cid in found_class_cars:
                    if cid in car_map:
                        resolved_car_names.add(car_map[cid])
            else:
                # Jeśli nie udało się rozpakować klasy, dajemy chociaż jej nazwę
                resolved_car_names.add(str(type_str).title())

    # Sortowanie alfabetyczne
    return sorted(list(resolved_car_names))

def send_to_discord(sessions, car_map, class_map):
    if not WEBHOOK_URL: return
    logger.info(f"📨 Wysyłanie {len(sessions)} sesji na Discorda...")

    embeds = []
    for i, s in enumerate(sessions, 1):
        name = s.get('session_name', 'Bez nazwy')
        track = s.get('track', {}).get('track_name', 'Nieznany tor')
        host = s.get('host', {}).get('display_name', 'Anonim')
        
        # --- ROZWIĄZYWANIE NAZW AUT ---
        car_names_list = resolve_cars_for_session(s, car_map, class_map)
        
        cars_str = ", ".join(car_names_list)
        
        # Limity Discorda (pole value max 1024 znaki)
        if len(cars_str) > 900: 
            cars_str = cars_str[:897] + "..."
        if not cars_str: 
            cars_str = "Brak danych / Wszystkie auta"

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
    
    # Pobieramy oba słowniki (Auta i Klasy)
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
