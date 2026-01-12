import os
import requests
import traceback
from iracingdataapi.client import irDataClient

# --- KONFIGURACJA ---
IRACING_EMAIL = os.environ["IRACING_EMAIL"]
IRACING_PASSWORD = os.environ["IRACING_PASSWORD"]
DISCORD_WEBHOOK = os.environ["DISCORD_WEBHOOK_URL"]

def send_discord(msg):
    try:
        requests.post(DISCORD_WEBHOOK, json={"content": msg})
    except Exception as e:
        print(f"❌ Błąd Discord: {e}")

def check_hosted():
    print("🔐 Próba logowania przez bibliotekę iracingdataapi...")
    
    try:
        # Biblioteka sama ogarnia logowanie i hashowanie hasła
        idc = irDataClient(username=IRACING_EMAIL, password=IRACING_PASSWORD)
        print("✅ Zalogowano pomyślnie!")
        
        # Pobieramy sesje hosted
        sessions = idc.hosted_sessions
        print(f"📊 Pobrana liczba sesji: {len(sessions)}")
        
        if not sessions:
            send_discord("ℹ️ Lista sesji jest pusta (brak wyników z API).")
            return

        # --- TEST: WYŚWIETLAMY 5 PIERWSZYCH SESJI ---
        send_discord(f"🧪 **TEST DZIAŁANIA (BIBLIOTEKA)** - Znaleziono {len(sessions)} sesji. Oto 5 przykładowych:")

        for s in sessions[:5]:
            # Wyciąganie danych przez bibliotekę jest prostsze (to zwykłe słowniki)
            session_name = s.get('session_name', 'No Name')
            track = s.get('track', {}).get('track_name', 'Unknown Track')
            host = s.get('host', {}).get('display_name', 'Unknown Host')
            is_private = s.get('password_protected', False)
            
            # Auta
            cars = s.get('cars', [])
            car_list = [c.get('car_name', 'Car') for c in cars]
            car_str = ", ".join(car_list)
            if len(car_str) > 60:
                car_str = car_str[:60] + "..."

            status_icon = "🔒" if is_private else "🔓"

            msg = (
                f"{status_icon} **{session_name}**\n"
                f"📍 {track}\n"
                f"🏎️ {car_str}\n"
                f"👤 {host}\n"
                "-----------------------"
            )
            send_discord(msg)
            print(f"-> Wysłano: {session_name}")

    except Exception as e:
        # Wyłapujemy błędy logowania lub API
        error_msg = f"❌ BŁĄD KRYTYCZNY: {str(e)}"
        print(error_msg)
        traceback.print_exc() # Zrzut błędu do logów GitHub
        send_discord(error_msg)

if __name__ == "__main__":
    check_hosted()
