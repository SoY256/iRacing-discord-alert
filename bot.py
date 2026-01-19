import os
import sys
import requests
import logging

# Konfiguracja loggera - żebyś widział w konsoli GitHuba co się dzieje
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Pobieranie zmiennych z GitHub Secrets
CLIENT_ID = os.environ.get("IR_CLIENT_ID")
CLIENT_SECRET = os.environ.get("IR_CLIENT_SECRET")
EMAIL = os.environ.get("IR_EMAIL")
PASSWORD = os.environ.get("IR_PASSWORD")
WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK")

# Endpointy iRacing
TOKEN_URL = "https://oauth.iracing.com/oauth2/token"
SESSIONS_URL = "https://members-ng.iracing.com/data/hosted/sessions"

def get_oauth_token():
    """Loguje się do iRacing i pobiera Bearer Token."""
    if not all([CLIENT_ID, CLIENT_SECRET, EMAIL, PASSWORD]):
        logger.error("❌ Brak zmiennych środowiskowych! Sprawdź GitHub Secrets.")
        sys.exit(1)

    payload = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "username": EMAIL,
        "password": PASSWORD,
        "scope": "data_server"
    }

    try:
        response = requests.post(TOKEN_URL, data=payload)
        response.raise_for_status()
        token = response.json().get("access_token")
        logger.info("✅ Zalogowano pomyślnie (OAuth2).")
        return token
    except Exception as e:
        logger.error(f"❌ Błąd logowania: {e}")
        if 'response' in locals():
            logger.error(f"Treść błędu serwera: {response.text}")
        sys.exit(1)

def send_to_discord(session, index):
    """Wysyła surowe dane o sesji na Discorda."""
    if not WEBHOOK_URL:
        return

    # Wyciąganie danych z JSON-a (bezpiecznie, z domyślnymi wartościami)
    sess_name = session.get('session_name', 'Bez nazwy')
    host = session.get('host', {}).get('display_name', 'Nieznany')
    track = session.get('track', {}).get('track_name', 'Nieznany tor')
    
    # Auta - czasem są w 'car_types', czasem w 'cars'
    cars_list = session.get('car_types', [])
    if not cars_list:
        cars_list = session.get('cars', [])
    
    # Tworzymy listę nazw aut
    car_names = []
    for c in cars_list:
        name = c.get('car_name', '') if isinstance(c, dict) else getattr(c, 'car_name', '')
        car_names.append(str(name))
    
    cars_str = ", ".join(car_names) if car_names else "Brak danych o autach"
    if len(cars_str) > 1000: cars_str = cars_str[:997] + "..." # Limit Discorda

    embed = {
        "title": f"Test Sesji #{index}",
        "color": 3447003, # Niebieski
        "fields": [
            {"name": "Nazwa", "value": sess_name, "inline": False},
            {"name": "Tor", "value": track, "inline": True},
            {"name": "Host", "value": host, "inline": True},
            {"name": "Auta", "value": cars_str, "inline": False}
        ],
        "footer": {"text": "Tryb Debugowania • Pierwsze 5 wyników"}
    }

    try:
        requests.post(WEBHOOK_URL, json={"embeds": [embed]})
        logger.info(f"Wysłano na Discord: {sess_name}")
    except Exception as e:
        logger.error(f"Błąd Discorda: {e}")

def main():
    logger.info("🚀 Start skryptu testowego...")
    
    # 1. Pobierz token
    token = get_oauth_token()
    
    # 2. Pobierz listę sesji
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "TestBot/1.0",
        "Content-Type": "application/json"
    }

    try:
        logger.info("Pobieranie listy sesji...")
        resp = requests.get(SESSIONS_URL, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        
        all_sessions = data.get('sessions', [])
        total_count = len(all_sessions)
        logger.info(f"Pobrano łącznie {total_count} sesji.")

        # 3. Weź tylko pierwsze 5 (BEZ FILTROWANIA)
        top_5 = all_sessions[:5]

        if not top_5:
            logger.info("Lista sesji jest pusta.")
            return

        logger.info("Wysyłam 5 pierwszych sesji na Discorda...")
        for i, session in enumerate(top_5, 1):
            send_to_discord(session, i)

    except Exception as e:
        logger.error(f"❌ Błąd podczas pobierania danych: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
