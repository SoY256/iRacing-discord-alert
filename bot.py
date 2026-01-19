import os
import sys
import requests
import logging
import hashlib
import base64

# Konfiguracja loggera
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Pobieranie zmiennych z GitHub Secrets + Strip
CLIENT_ID = os.environ.get("IR_CLIENT_ID", "").strip()
CLIENT_SECRET = os.environ.get("IR_CLIENT_SECRET", "").strip()
EMAIL = os.environ.get("IR_EMAIL", "").strip()
PASSWORD = os.environ.get("IR_PASSWORD", "").strip()
WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK", "").strip()

# Endpointy
TOKEN_URL = "https://oauth.iracing.com/oauth2/token"
SESSIONS_URL = "https://members-ng.iracing.com/data/hosted/sessions"

def encode_password_standard(secret, modifier):
    """
    Realizuje haszowanie: STANDARD Base64( SHA256( secret + modifier.lower() ) )
    """
    if not secret or not modifier:
        return ""
    
    initial_text = secret + modifier.lower()
    hash_digest = hashlib.sha256(initial_text.encode('utf-8')).digest()
    
    # Używamy standardowego b64encode (z + i /) - bo serwer odrzucił URL-safe
    encoded = base64.b64encode(hash_digest).decode('utf-8')
    return encoded

def get_oauth_token():
    # --- DEBUGOWANIE ZMIENNYCH (Bezpieczne) ---
    # Sprawdzamy czy sekrety się wczytały
    logger.info(f"🔍 DEBUG: Client ID (pierwsze 3 znaki): {CLIENT_ID[:3]}...")
    logger.info(f"🔍 DEBUG: Client Secret (długość): {len(CLIENT_SECRET)} znaków")
    
    if not all([CLIENT_ID, CLIENT_SECRET, EMAIL, PASSWORD]):
        logger.error("❌ Brak zmiennych środowiskowych! Sprawdź GitHub Secrets.")
        sys.exit(1)

    # 1. Kodowanie Hasła (Standard Base64)
    # Wersja 4.0 padła przez URL-Safe, Wersja 5.0 padła przez haszowanie Secretu.
    # Teraz robimy: Hasło -> Standard Base64.
    hashed_password = encode_password_standard(PASSWORD, EMAIL)
    
    # 2. Client Secret -> SUROWY
    # Wracamy do oryginału, bo błąd 401 w wer. 5.0 sugerował, że haszowanie go psuje.
    
    payload = {
        "grant_type": "password_limited",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET, # <--- SUROWY
        "username": EMAIL,
        "password": hashed_password     # <--- ZAHASZOWANY (Standard)
    }

    try:
        logger.info(f"🚀 Wysyłam żądanie logowania...")
        response = requests.post(TOKEN_URL, data=payload)
        response.raise_for_status()
        
        data = response.json()
        token = data.get("access_token")
        
        if not token:
            logger.error(f"❌ Odpowiedź nie zawiera tokenu. Dane: {data}")
            sys.exit(1)
            
        logger.info("✅ Zalogowano pomyślnie (Password Limited Flow).")
        return token

    except requests.exceptions.HTTPError as e:
        logger.error(f"❌ Błąd autoryzacji (HTTP {response.status_code}): {e}")
        logger.error(f"Treść błędu serwera: {response.text}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Inny błąd logowania: {e}")
        sys.exit(1)

def send_to_discord(session, index):
    if not WEBHOOK_URL: return

    sess_name = session.get('session_name', 'Bez nazwy')
    host = session.get('host', {}).get('display_name', 'Nieznany')
    track = session.get('track', {}).get('track_name', 'Nieznany tor')
    
    cars_list = session.get('car_types', [])
    if not cars_list: cars_list = session.get('cars', [])
    
    car_names = [str(c.get('car_name', '')) if isinstance(c, dict) else getattr(c, 'car_name', '') for c in cars_list]
    cars_str = ", ".join(car_names) if car_names else "Brak danych"
    if len(cars_str) > 1000: cars_str = cars_str[:997] + "..."

    embed = {
        "title": f"Test Sesji #{index}",
        "color": 3447003,
        "fields": [
            {"name": "Nazwa", "value": sess_name, "inline": False},
            {"name": "Tor", "value": track, "inline": True},
            {"name": "Host", "value": host, "inline": True},
            {"name": "Auta", "value": cars_str, "inline": False}
        ],
        "footer": {"text": "iRacing Bot • Hybrid Fix"}
    }

    try:
        requests.post(WEBHOOK_URL, json={"embeds": [embed]})
        logger.info(f"Wysłano na Discord: {sess_name}")
    except Exception as e:
        logger.error(f"Błąd Discorda: {e}")

def main():
    logger.info("🚀 Start skryptu (Tryb: Raw Secret + Standard Hash)...")
    token = get_oauth_token()
    
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "HostedSessionsNotifier/1.0",
        "Content-Type": "application/json"
    }

    try:
        logger.info("Pobieranie listy sesji...")
        resp = requests.get(SESSIONS_URL, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        
        all_sessions = data.get('sessions', [])
        logger.info(f"Pobrano łącznie {len(all_sessions)} sesji.")

        top_5 = all_sessions[:5]
        if not top_5:
            logger.info("Lista sesji jest pusta.")
            return

        for i, session in enumerate(top_5, 1):
            send_to_discord(session, i)

    except Exception as e:
        logger.error(f"❌ Błąd API Danych: {e}")
        if 'resp' in locals():
            logger.error(f"Treść błędu API: {resp.text}")
        sys.exit(1)

if __name__ == "__main__":
    main()
