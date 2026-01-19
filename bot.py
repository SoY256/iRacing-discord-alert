import os
import sys
import requests
import logging
import hashlib
import base64
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Pobieranie danych
CLIENT_ID_FULL = os.environ.get("IR_CLIENT_ID", "").strip() # To ma końcówkę -pwlimited
CLIENT_SECRET = os.environ.get("IR_CLIENT_SECRET", "").strip()
EMAIL = os.environ.get("IR_EMAIL", "").strip()
PASSWORD = os.environ.get("IR_PASSWORD", "").strip()
WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK", "").strip()

TOKEN_URL = "https://oauth.iracing.com/oauth2/token"
SESSIONS_URL = "https://members-ng.iracing.com/data/hosted/sessions"

def encode_credential(secret, modifier):
    """Standard Base64( SHA256( secret + modifier.lower() ) )"""
    if not secret or not modifier: return ""
    initial_text = secret + modifier.lower()
    hash_digest = hashlib.sha256(initial_text.encode('utf-8')).digest()
    return base64.b64encode(hash_digest).decode('utf-8')

def try_payload_variant(name, id_to_send, salt_for_secret):
    """
    name: Nazwa testu
    id_to_send: Co wstawiamy w pole json 'client_id'
    salt_for_secret: Czym haszujemy sekret
    """
    logger.info(f"🧪 TEST: {name}")
    logger.info(f"   👉 Wysyłam ID: '{id_to_send}'")
    logger.info(f"   👉 Solę sekret: '{salt_for_secret}'")

    # 1. Hasło zawsze solimy mailem
    hashed_password = encode_credential(PASSWORD, EMAIL)
    
    # 2. Sekret solimy wybraną metodą
    hashed_secret = encode_credential(CLIENT_SECRET, salt_for_secret)

    payload = {
        "grant_type": "password_limited",
        "client_id": id_to_send,        # <--- TU JEST ZMIANA (Wysyłamy krótki numer)
        "client_secret": hashed_secret,
        "username": EMAIL,
        "password": hashed_password
    }

    try:
        response = requests.post(TOKEN_URL, data=payload)
        
        if response.status_code == 200:
            logger.info(f"✅✅✅ SUKCES! ZADZIAŁAŁO!")
            return response.json().get("access_token")
        elif response.status_code == 401:
             logger.warning(f"   ⛔ 401: {response.json().get('error', 'Unknown error')}")
        else:
             logger.error(f"   ❌ {response.status_code}: {response.text}")
    except Exception as e:
        logger.error(f"   ❌ Błąd połączenia: {e}")
    
    return None

def main():
    logger.info("🚀 Start skryptu 'ID SWAP'...")

    # Wyciągamy sam numer (1303987)
    numeric_match = re.match(r"^(\d+)", CLIENT_ID_FULL)
    SHORT_ID = numeric_match.group(1) if numeric_match else CLIENT_ID_FULL

    # --- WARIANT 1: Wyślij KRÓTKIE ID, posól PEŁNYM ID ---
    # (Najbardziej prawdopodobne: serwer szuka po ID klienta, ale weryfikuje hashm z pełną nazwą)
    token = try_payload_variant("A: Wyślij ShortID, Sól=FullID", SHORT_ID, CLIENT_ID_FULL)

    # --- WARIANT 2: Wyślij KRÓTKIE ID, posól KRÓTKIM ID ---
    if not token:
        token = try_payload_variant("B: Wyślij ShortID, Sól=ShortID", SHORT_ID, SHORT_ID)

    if not token:
        logger.error("❌ Nadal 401. To oznacza, że problem leży w ważności danych.")
        logger.error("👉 Czy na pewno 'Client Secret' jest nadal ważny? (Link działał 24h)")
        sys.exit(1)

    # Sukces - pobieramy dane
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(SESSIONS_URL, headers=headers)
        if r.status_code == 200:
            count = len(r.json().get('sessions', []))
            logger.info(f"📊 Pobrano {count} sesji. Bot działa!")
            if WEBHOOK_URL:
                requests.post(WEBHOOK_URL, json={"content": "✅ iRacing Bot: Zalogowano (Fix ID)!"})
    except:
        pass

if __name__ == "__main__":
    main()
