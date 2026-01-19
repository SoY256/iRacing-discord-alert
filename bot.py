import os
import sys
import requests
import logging
import hashlib
import base64

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Pobieramy SUROWE dane (bez usuwania spacji na razie)
CLIENT_ID = os.environ.get("IR_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("IR_CLIENT_SECRET", "")
EMAIL = os.environ.get("IR_EMAIL", "")
PASSWORD = os.environ.get("IR_PASSWORD", "")
WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK", "")

TOKEN_URL = "https://oauth.iracing.com/oauth2/token"
SESSIONS_URL = "https://members-ng.iracing.com/data/hosted/sessions"

def encode_credential(secret, modifier):
    """Standard Base64( SHA256( secret + modifier.lower() ) )"""
    if not secret or not modifier: return ""
    # Usuwamy białe znaki przed haszowaniem, bo to standard
    initial_text = secret.strip() + modifier.strip().lower()
    hash_digest = hashlib.sha256(initial_text.encode('utf-8')).digest()
    return base64.b64encode(hash_digest).decode('utf-8')

def try_auth(desc, payload):
    logger.info(f"🔄 Próba: {desc}")
    try:
        response = requests.post(TOKEN_URL, data=payload)
        if response.status_code == 200:
            logger.info("✅ SUKCES! Zalogowano!")
            return response.json().get("access_token")
        else:
            logger.error(f"❌ {desc} -> Błąd {response.status_code}: {response.text}")
    except Exception as e:
        logger.error(f"❌ Błąd sieci: {e}")
    return None

def main():
    logger.info("🕵️ LUSTRO DANYCH (Co widzi skrypt?):")
    
    # --- ANALIZA DŁUGOŚCI ---
    secret_len = len(CLIENT_SECRET)
    logger.info(f"   Długość Client Secret: {secret_len} (Ty mówisz: 43)")
    
    if secret_len > 0:
        first_char = CLIENT_SECRET[0]
        last_char = CLIENT_SECRET[-1]
        logger.info(f"   Pierwszy znak: '{first_char}'")
        logger.info(f"   OSTATNI ZNAK:  '{last_char}' (Kod ASCII: {ord(last_char)})")
        
        if secret_len == 42:
            logger.warning("⚠️ ALARM: Brakuje 1 znaku! Sprawdź w mailu co jest po znaku '" + last_char + "'")
    else:
        logger.error("❌ Sekret jest pusty!")
        sys.exit(1)

    # --- PRÓBY LOGOWANIA ---
    # Logowanie z haszowaniem OBU wartości (To dało nam błąd 401, więc to poprawny protokół)
    # Jeśli naprawisz sekret w GitHubie, to zadziała.
    
    hashed_password = encode_credential(PASSWORD, EMAIL)
    hashed_secret = encode_credential(CLIENT_SECRET, CLIENT_ID) # Używamy surowego (może mieć 43 znaki)

    payload_hashed = {
        "grant_type": "password_limited",
        "client_id": CLIENT_ID.strip(),
        "client_secret": hashed_secret,
        "username": EMAIL.strip(),
        "password": hashed_password
    }
    
    token = try_auth("Metoda Hashed (Standard)", payload_hashed)

    # Jeśli token zdobyty -> Pobieramy sesje
    if token:
        headers = {"Authorization": f"Bearer {token}"}
        try:
            r = requests.get(SESSIONS_URL, headers=headers)
            count = len(r.json().get('sessions', []))
            logger.info(f"📊 Pobrano {count} sesji. Bot działa!")
            
            # Test Discord
            if WEBHOOK_URL and count > 0:
                requests.post(WEBHOOK_URL, json={"content": "✅ Bot połączony z iRacing!"})
        except:
            pass
    else:
        logger.error("❌ Nie udało się zalogować. Popraw Client Secret w GitHub Secrets!")
        sys.exit(1)

if __name__ == "__main__":
    main()
