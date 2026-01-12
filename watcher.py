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
        
        # --- TU BYŁ BŁĄD: dodano nawiasy () ---
        sessions = idc.hosted_sessions() 
        # --------------------------------------

        print(f"📊 Pobrana liczba sesji: {len(sessions)}")
        
        if not sessions:
            send_discord("ℹ️ Lista sesji jest pusta (brak wyników z API).")
            return

        # --- TEST: WYŚWIETLAMY 5 PIERWSZYCH SESJI ---
        send_discord(f"🧪 **TEST DZIAŁANIA** - Znaleziono {len(sessions)} sesji. Oto 5 przykładowych:")

        for s in sessions[:5]:
            # Wyciąganie danych
            session_name = s.get('session_name', 'No Name')
            track = s.get('track', {}).get('track_name', 'Unknown Track')
            host = s.get('host', {}).get('display_name', 'Unknown Host')
            is_private = s.get('private_session_id') is not None # Biblioteka może zwracać to inaczej, sprawdzamy
            
            # W tej bibliotece struktura aut może być nieco inna, więc robimy bezpiecznie:
            cars = s.get('car_types', []) 
            # Jeśli to pusta lista, spróbujmy innego pola (zależnie od wersji API)
            if not cars:
                 cars = s.get('cars', [])

            car_list = []
            for c in cars:
                # Czasem jest to słownik, czasem obiekt
                if isinstance(c, dict):
                    car_list.append(c.get('car_name', 'Car'))
                elif hasattr(c, 'car_name'):
                    car_list.append(c.car_name)
                else:
                    car_list.append("Unknown Car")

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
        traceback.print_exc() 
        send_discord(error_msg)

if __name__ == "__main__":
    check_hosted()
