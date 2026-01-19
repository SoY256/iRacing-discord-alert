import os
import sys
import requests
import logging
import hashlib
import base64

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- POBIERANIE DANYCH ---
# Client ID wpisujemy NA SZTYWNO, żeby wykluczyć błąd w GitHub Secrets
# To jest wartość skopiowana prosto z Twojego maila.
HARDCODED_CLIENT_ID = "1303987-pwlimited"

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

def main():
    logger.info("🚀 Start skryptu 'BACK TO BASICS'...")
    logger.info(f"👉 Używam sztywnego Client ID: '{HARDCODED_CLIENT_ID}'")
    
    # Weryfikacja długości sekretu (dla pewności)
    if len(CLIENT_SECRET) != 42:
        logger.warning(f"⚠️ UWAGA: Client Secret ma {len(CLIENT_SECRET)} znaków (oczekiwano 42).")
    else:
        logger.info("✅ Client Secret ma poprawną długość (42 znaki).")

    # 1. Hasło solimy mailem
    hashed_password = encode_credential(PASSWORD, EMAIL)
    
    # 2. Sekret solimy PEŁNYM Client ID (tak jak w dokumentacji)
    # Wcześniej to nie działało przez spacje, teraz musi zadziałać.
    hashed_secret = encode_credential(CLIENT_SECRET, HARDCODED_CLIENT_ID)

    payload = {
        "grant_type": "password_limited",
        "client_id": HARDCODED_CLIENT_ID, # Wysyłamy pełne ID
        "client_secret": hashed_secret,   # Solimy pełnym ID
        "username": EMAIL,
        "password": hashed_password
    }

    try:
        response = requests.post(TOKEN_URL, data=payload)
        
        if response.status_code == 200:
            token = response.json().get("access_token")
            logger.info("✅✅✅ SUKCES! ZALOGOWANO!")
            logger.info("🎉 Problem rozwiązany. To była kwestia spacji przy standardowym configu.")
            
            # Test pobrania danych
            headers = {"Authorization": f"Bearer {token}"}
            r = requests.get(SESSIONS_URL, headers=headers)
            if r.status_code == 200:
                count = len(r.json().get('sessions', []))
                logger.info(f"📊 Widzę {count} sesji.")
                if WEBHOOK_URL:
                    requests.post(WEBHOOK_URL, json={"content": "✅ iRacing Bot: Zalogowano OSTATECZNIE!"})
            
        elif response.status_code == 401:
            logger.error("❌ Błąd 401: invalid_client")
            logger.error("💀 DIAGNOZA KOŃCOWA: Twój Client Secret jest BŁĘDNY lub WYGASŁ.")
            logger.error("👉 Musisz napisać do supportu iRacing o wygenerowanie NOWEGO sekretu.")
            logger.error("👉 Link do sekretu działa tylko 24h. Jeśli kliknąłeś go wcześniej, już nie zadziała.")
            
        else:
            logger.error(f"❌ Inny błąd: {response.status_code} - {response.text}")

    except Exception as e:
        logger.error(f"❌ Błąd połączenia: {e}")

if __name__ == "__main__":
    main()
