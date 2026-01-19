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

# Pobieranie danych
CLIENT_ID = os.environ.get("IR_CLIENT_ID", "").strip()
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

def try_combo(name, secret_salt, username_field, password_salt):
    """
    Testuje konkretną kombinację:
    - Czym solimy sekret? (secret_salt)
    - Co wysyłamy jako username? (email czy id?)
    - Czym solimy hasło? (password_salt)
    """
    logger.info(f"🧪 TEST: {name}")
    
    # 1. Przygotowanie hashy
    hashed_secret = encode_credential(CLIENT_SECRET, secret_salt)
    hashed_password = encode_credential(PASSWORD, password_salt)
    
    payload = {
        "grant_type": "password_limited",
        "client_id": CLIENT_ID,
        "client_secret": hashed_secret,
        "username": username_field,
        "password": hashed_password
    }

    try:
        response = requests.post(TOKEN_URL, data=payload)
        
        if response.status_code == 200:
            logger.info(f"✅✅✅ SUKCES! ZADZIAŁAŁA KOMBINACJA: {name}")
            return response.json().get("access_token")
        
        elif response.status_code == 401:
            err = response.json().get('error', '')
            logger.warning(f"   ⛔ 401: {err} (To nie to)")
        else:
            logger.error(f"   ❌ {response.status_code}: {response.text}")

    except Exception as e:
        logger.error(f"   ❌ Błąd połączenia: {e}")
    
    return None

def main():
    logger.info("🚀 Start skryptu MATRIX (Testowanie kombinacji)...")
    
    # Wyciąganie samego numeru klienta (np. 1303987)
    numeric_match = re.match(r"^(\d+)", CLIENT_ID)
    CUSTOMER_ID = numeric_match.group(1) if numeric_match else CLIENT_ID

    # Lista kombinacji do sprawdzenia
    # Format: (Nazwa, Sól Sekretu, Pole Username, Sól Hasła)
    
    combos = [
        # 1. Klasyk (To testowaliśmy najczęściej)
        ("A: Sól=FullID, User=Email", CLIENT_ID, EMAIL, EMAIL),
        
        # 2. Sól to numer ID (Bardzo prawdopodobne!)
        ("B: Sól=NumID, User=Email", CUSTOMER_ID, EMAIL, EMAIL),
        
        # 3. Sól to Email (Czasem tak jest)
        ("C: Sól=Email, User=Email", EMAIL, EMAIL, EMAIL),
        
        # 4. Username to ID (Rzadkie w pwlimited, ale możliwe)
        ("D: Sól=FullID, User=NumID", CLIENT_ID, CUSTOMER_ID, EMAIL),
        
        # 5. Hasło solone przez ID (Zamiast mailem)
        ("E: Sól=FullID, PassSalt=NumID", CLIENT_ID, EMAIL, CUSTOMER_ID),
        
        # 6. Wszystko na numerach
        ("F: Sól=NumID, User=NumID, PassSalt=NumID", CUSTOMER_ID, CUSTOMER_ID, CUSTOMER_ID)
    ]

    token = None
    for combo in combos:
        token = try_combo(*combo)
        if token:
            break # Mamy to!
            
    if not token:
        logger.error("❌ Wszystkie 6 kombinacji zawiodło. Błąd leży poza logiką skryptu.")
        sys.exit(1)

    # Sukces - wysyłamy info
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(SESSIONS_URL, headers=headers)
        if r.status_code == 200:
            logger.info("📊 Pobrano sesje poprawnie.")
            if WEBHOOK_URL:
                requests.post(WEBHOOK_URL, json={"content": "✅ iRacing Bot: Zalogowano poprawnie!"})
    except:
        pass

if __name__ == "__main__":
    main()
