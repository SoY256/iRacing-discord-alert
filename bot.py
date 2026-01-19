import os
import sys
import requests
import logging
import hashlib
import base64
import re

# Konfiguracja loggera
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Pobieranie danych (z czyszczeniem spacji)
CLIENT_ID = os.environ.get("IR_CLIENT_ID", "").strip()
CLIENT_SECRET = os.environ.get("IR_CLIENT_SECRET", "").strip()
EMAIL = os.environ.get("IR_EMAIL", "").strip()
PASSWORD = os.environ.get("IR_PASSWORD", "").strip()
WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK", "").strip()

TOKEN_URL = "https://oauth.iracing.com/oauth2/token"
SESSIONS_URL = "https://members-ng.iracing.com/data/hosted/sessions"

def encode_credential(secret, modifier):
    """
    Standard Base64( SHA256( secret + modifier.lower() ) )
    """
    if not secret or not modifier: return ""
    # Upewniamy się, że modifier jest lowercase (standard iRacing)
    initial_text = secret + modifier.lower()
    hash_digest = hashlib.sha256(initial_text.encode('utf-8')).digest()
    return base64.b64encode(hash_digest).decode('utf-8')

def attempt_login(salt_description, salt_value):
    """Próbuje zalogować się używając konkretnego 'solenia' dla sekretu."""
    
    logger.info(f"🔄 PRÓBA LOGOWANIA: {salt_description}")
    logger.info(f"   Użyta sól (Modifier): '{salt_value}'")

    # 1. Haszujemy hasło (zawsze solone mailem)
    hashed_password = encode_credential(PASSWORD, EMAIL)
    
    # 2. Haszujemy sekret (używając podanej soli)
    hashed_client_secret = encode_credential(CLIENT_SECRET, salt_value)

    payload = {
        "grant_type": "password_limited",
        "client_id": CLIENT_ID,          # Tu zawsze wysyłamy pełne ID
        "client_secret": hashed_client_secret, # Tu wysyłamy wynik haszowania
        "username": EMAIL,
        "password": hashed_password
    }

    try:
        response = requests.post(TOKEN_URL, data=payload)
        
        if response.status_code == 200:
            logger.info(f"✅ SUKCES! Zadziałała metoda: {salt_description}")
            return response.json().get("access_token")
        
        elif response.status_code == 401:
            logger.warning(f"⛔ Błąd 401 (Nieautoryzowany). To nie ta sól.")
        else:
            logger.error(f"❌ Błąd {response.status_code}: {response.text}")
            
    except Exception as e:
        logger.error(f"❌ Błąd połączenia: {e}")
    
    return None

def main():
    logger.info("🚀 Start skryptu 'Dual-Login'...")
    
    # Wyciągamy sam numer z ID (np. 1303987 z 1303987-pwlimited)
    numeric_id = re.match(r"^(\d+)", CLIENT_ID)
    customer_id = numeric_id.group(1) if numeric_id else CLIENT_ID

    # --- PRÓBA 1: Solenie PEŁNYM Client ID ---
    # (To robiliśmy do tej pory, dawało 401, ale sprawdzamy dla pewności)
    token = attempt_login("Metoda A (Pełne ID)", CLIENT_ID)

    # --- PRÓBA 2: Solenie SAMYM NUMEREM ---
    # (To jest najbardziej prawdopodobne rozwiązanie!)
    if not token:
        print("-" * 30)
        token = attempt_login("Metoda B (Tylko Numer Klienta)", customer_id)

    if not token:
        logger.error("❌ Obie metody zawiodły. Sprawdź hasło użytkownika (czy na pewno dobre?).")
        sys.exit(1)

    # Jeśli mamy token -> Pobieramy sesje
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "HostedSessionsNotifier/1.0",
        "Content-Type": "application/json"
    }

    try:
        logger.info("📥 Pobieranie listy sesji...")
        resp = requests.get(SESSIONS_URL, headers=headers)
        resp.raise_for_status()
        sessions = resp.json().get('sessions', [])
        logger.info(f"✅ POŁĄCZONO! Widzę {len(sessions)} sesji.")
        
        if sessions and WEBHOOK_URL:
            s = sessions[0]
            track = s.get('track', {}).get('track_name', 'Unknown')
            requests.post(WEBHOOK_URL, json={"content": f"✅ Bot działa! Przykładowa sesja: {track}"})
            logger.info("Wysłano test na Discorda.")

    except Exception as e:
        logger.error(f"❌ Błąd API Danych: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
