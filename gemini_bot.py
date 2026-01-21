import os
import sys
import requests
import hashlib
import base64
import logging
import time
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

def get_car_mapping(token):
    raw_data = get_data_from_link(CARS_ASSETS_URL, token, "Słownik Aut")
    if not raw_data: return {}
    
    car_map = {}
    for car in raw_data:
        c_id = car.get('car_id')
        c_name = car.get('car_name')
        if c_id and c_name:
            car_map[c_id] = c_name # Kluczem jest int
            car_map[str(c_id)] = c_name # Kluczem jest też string (dla bezpieczeństwa)
            
    logger.info(f"📚 Zbudowano mapę nazw dla {len(car_map)} samochodów.")
    return car_map

def send_to_discord(sessions, car_map):
    if not WEBHOOK_URL: return
    logger.info(f"📨 Wysyłanie {len(sessions)} sesji na Discorda...")

    # --- DEBUGOWANIE STRUKTURY (To nam powie prawdę) ---
    if sessions:
        first_session = sessions[0]
        cars_debug = first_session.get('car_types', []) or first_session.get('cars', [])
        logger.info("🔍🔍🔍 DEBUG STRUKTURY AUT (Spójrz tutaj):")
        logger.info(json.dumps(cars_debug, indent=2))
        logger.info("🔍🔍🔍 KONIEC DEBUGA")
    # ---------------------------------------------------

    embeds = []
    for i, s in enumerate(sessions, 1):
        name = s.get('session_name', 'Bez nazwy')
        track = s.get('track', {}).get('track_name', 'Nieznany tor')
        host = s.get('host', {}).get('display_name', 'Anonim')
        
        session_cars = s.get('car_types', []) or s.get('cars', [])
        car_names_list = []
        
        for car_entry in session_cars:
            c_id = None
            
            # Logika "Sherlocka Holmesa" - szukamy ID wszędzie
            if isinstance(car_entry, dict):
                # Próbujemy różnych nazw kluczy, które iRacing stosuje zamiennie
                c_id = car_entry.get('car_id') or car_entry.get('id') or car_entry.get('car_type_id')
            elif isinstance(car_entry, int):
                # Czasem lista to po prostu [145, 20, 30]
                c_id = car_entry
            
            # Próba mapowania
            if c_id is not None:
                # Konwersja na int i str dla pewności trafienia w słownik
                if c_id in car_map:
                    car_names_list.append(car_map[c_id])
                elif str(c_id) in car_map:
                    car_names_list.append(car_map[str(c_id)])
                else:
                    car_names_list.append(f"Car ID {c_id}") # Przynajmniej zobaczymy numerek
            else:
                car_names_list.append("Błąd ID")

        # Usuwanie duplikatów (set) i sortowanie
        car_names_list = sorted(list(set(car_names_list)))
        
        cars_str = ", ".join(car_names_list)
        if len(cars_str) > 500: cars_str = cars_str[:497] + "..."
        if not cars_str: cars_str = "Brak danych"

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
    car_map = get_car_mapping(token)
    
    data = get_data_from_link(SESSIONS_URL, token, "Lista Sesji")
    if not data: sys.exit(1)

    sessions = data.get('sessions', [])
    logger.info(f"📊 Znaleziono łącznie {len(sessions)} sesji.")
    
    top_5 = sessions[:5]
    if top_5:
        send_to_discord(top_5, car_map)
    else:
        logger.info("ℹ️ Brak sesji.")

if __name__ == "__main__":
    main()
