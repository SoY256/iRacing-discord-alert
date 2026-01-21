import os
import sys
import requests
import hashlib
import base64
import logging
import time

# Konfiguracja logowania
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

# --- POBIERANIE ZMIENNYCH ---
CLIENT_ID = os.environ.get("IR_CLIENT_ID", "").strip()
CLIENT_SECRET = os.environ.get("IR_CLIENT_SECRET", "").strip()
EMAIL = os.environ.get("IR_EMAIL", "").strip()
PASSWORD = os.environ.get("IR_PASSWORD", "").strip()
WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK", "").strip()

# Stałe
TOKEN_URL = "https://oauth.iracing.com/oauth2/token"
# ZMIANA: Używamy endpointu, który zwraca listę wszystkich publicznych sesji
SESSIONS_URL = "https://members-ng.iracing.com/data/hosted/combined_sessions"

def generate_hash(secret, salt):
    """SHA-256(secret + lower(salt)) -> Standard Base64"""
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

def get_data_from_link(url, token):
    """
    Kluczowa funkcja:
    1. Pyta API o dane.
    2. Jeśli API zwróci 'link', pobiera dane z tego linku.
    """
    headers = {"Authorization": f"Bearer {token}"}
    
    logger.info(f"➡️ Pytam API: {url}")
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()

    # Sprawdzamy, czy dostaliśmy LINK (mechanizm iRacing)
    if 'link' in data:
        link_url = data['link']
        logger.info("🔗 Otrzymano link do danych. Pobieranie właściwej treści...")
        
        # Pobieramy dane z S3 (bez tokenu Bearer, to publiczny link S3)
        s3_resp = requests.get(link_url)
        s3_resp.raise_for_status()
        return s3_resp.json()
    
    # Jeśli nie ma linku, zwracamy to co przyszło (rzadki przypadek w Data API)
    return data

def send_to_discord(sessions):
    if not WEBHOOK_URL: return
    logger.info(f"📨 Wysyłanie {len(sessions)} sesji na Discorda...")

    embeds = []
    for i, s in enumerate(sessions, 1):
        name = s.get('session_name', 'Bez nazwy')
        track = s.get('track', {}).get('track_name', 'Nieznany tor')
        host = s.get('host', {}).get('display_name', 'Anonim')
        
        # Obsługa aut
        cars = s.get('car_types', []) or s.get('cars', [])
        car_list = [str(c.get('car_name', 'Auto')) for c in cars]
        cars_str = ", ".join(car_list)
        if len(cars_str) > 100: cars_str = cars_str[:97] + "..."

        embed = {
            "title": f"🏎️ Sesja #{i}: {name}",
            "color": 3066993,
            "fields": [
                {"name": "📍 Tor", "value": track, "inline": True},
                {"name": "👤 Host", "value": host, "inline": True},
                {"name": "🚗 Auta", "value": cars_str or "Brak danych", "inline": False}
            ]
        }
        embeds.append(embed)

    try:
        requests.post(WEBHOOK_URL, json={"embeds": embeds})
        logger.info("✅ Powiadomienie wysłane!")
    except Exception as e:
        logger.error(f"❌ Błąd Discorda: {e}")

def main():
    token = get_access_token()
    
    try:
        # Używamy nowej funkcji z obsługą linków
        data = get_data_from_link(SESSIONS_URL, token)
        
        # Pobieramy listę sesji z właściwego JSON-a
        sessions = data.get('sessions', [])
        
        logger.info(f"📊 Znaleziono łącznie {len(sessions)} sesji.")
        
        top_5 = sessions[:5]
        if top_5:
            send_to_discord(top_5)
        else:
            logger.info("ℹ️ Lista sesji jest pusta (0 wyników w pliku S3).")

    except Exception as e:
        logger.error(f"❌ Błąd: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
