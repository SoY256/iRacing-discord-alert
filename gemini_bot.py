import os
import sys
import requests
import hashlib
import base64
import logging

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
SESSIONS_URL = "https://members-ng.iracing.com/data/hosted/sessions"

def generate_hash(secret, salt):
    """
    Implementacja Twojego algorytmu JS w Pythonie:
    SHA-256(secret + lower(salt)) -> Standard Base64
    """
    if not secret or not salt:
        return ""
        
    # JS: const normalizedSalt = salt.trim().toLowerCase();
    salt_normalized = salt.strip().lower()
    
    # JS: const data = encoder.encode(secret + normalizedSalt);
    text_to_hash = secret + salt_normalized
    
    # JS: crypto.subtle.digest("SHA-256", data);
    digest = hashlib.sha256(text_to_hash.encode('utf-8')).digest()
    
    # JS: btoa(binary) -> Standard Base64
    return base64.b64encode(digest).decode('utf-8')

def get_access_token():
    logger.info("🔐 Generowanie skrótów (Hashing)...")
    
    # 1. Haszowanie hasła (Sól = Email)
    hashed_password = generate_hash(PASSWORD, EMAIL)
    
    # 2. Haszowanie sekretu (Sól = Client ID)
    hashed_client_secret = generate_hash(CLIENT_SECRET, CLIENT_ID)

    # Parametry zgodne z Twoim Postmanem (image_b84177.png)
    payload = {
        "grant_type": "password_limited",
        "username": EMAIL,
        "password": hashed_password,
        "scope": "iracing.auth",         # <--- WAŻNE! To widać na screenie
        "client_id": CLIENT_ID,
        "client_secret": hashed_client_secret
    }

    try:
        logger.info("🚀 Wysyłam żądanie logowania...")
        # requests domyślnie używa 'application/x-www-form-urlencoded' dla parametru 'data'
        response = requests.post(TOKEN_URL, data=payload)
        response.raise_for_status()
        
        token = response.json().get("access_token")
        logger.info("✅ Zalogowano pomyślnie!")
        return token
        
    except requests.exceptions.HTTPError as e:
        logger.error(f"❌ Błąd logowania: {e}")
        logger.error(f"Odpowiedź serwera: {response.text}")
        sys.exit(1)

def send_to_discord(sessions):
    if not WEBHOOK_URL:
        logger.warning("⚠️ Brak Webhooka Discorda.")
        return

    logger.info(f"📨 Wysyłanie {len(sessions)} sesji na Discorda...")

    embeds = []
    for i, s in enumerate(sessions, 1):
        # Wyciąganie danych (bezpieczne, z domyślnymi wartościami)
        name = s.get('session_name', 'Bez nazwy')
        track = s.get('track', {}).get('track_name', 'Nieznany tor')
        host = s.get('host', {}).get('display_name', 'Anonim')
        
        # Obsługa aut (czasem car_types, czasem cars)
        cars = s.get('car_types', []) or s.get('cars', [])
        car_list = [str(c.get('car_name', 'Auto')) for c in cars]
        cars_str = ", ".join(car_list)
        
        # Przycinanie tekstu aut jeśli za długi
        if len(cars_str) > 100:
            cars_str = cars_str[:97] + "..."

        embed = {
            "title": f"🏎️ Sesja #{i}: {name}",
            "color": 3066993, # Zielony iRacing
            "fields": [
                {"name": "📍 Tor", "value": track, "inline": True},
                {"name": "👤 Host", "value": host, "inline": True},
                {"name": "🚗 Auta", "value": cars_str or "Brak danych", "inline": False}
            ]
        }
        embeds.append(embed)

    try:
        # Discord API przyjmuje listę embedów
        requests.post(WEBHOOK_URL, json={"embeds": embeds})
        logger.info("✅ Powiadomienie wysłane!")
    except Exception as e:
        logger.error(f"❌ Błąd Discorda: {e}")

def main():
    # 1. Logowanie
    token = get_access_token()
    
    # 2. Pobieranie sesji
    headers = {"Authorization": f"Bearer {token}"}
    try:
        logger.info("📥 Pobieranie listy sesji...")
        resp = requests.get(SESSIONS_URL, headers=headers)
        resp.raise_for_status()
        
        data = resp.json()
        sessions = data.get('sessions', [])
        logger.info(f"📊 Znaleziono łącznie {len(sessions)} sesji.")
        
        # 3. Wybór pierwszych 5
        top_5 = sessions[:5]
        
        if top_5:
            send_to_discord(top_5)
        else:
            logger.info("ℹ️ Brak aktywnych sesji do wysłania.")

    except Exception as e:
        logger.error(f"❌ Błąd pobierania danych: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
