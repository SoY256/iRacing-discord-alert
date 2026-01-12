import os
import requests
import sys

# --- KONFIGURACJA ---
IRACING_COOKIE = os.environ.get("IRACING_COOKIE", "")
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK_URL", "")

def send_discord(msg):
    try:
        if DISCORD_WEBHOOK:
            requests.post(DISCORD_WEBHOOK, json={"content": msg})
        print(msg)
    except Exception as e:
        print(f"❌ Błąd Discord: {e}")

def check_hosted():
    if not IRACING_COOKIE:
        print("❌ BŁĄD: Brak zmiennej IRACING_COOKIE w Secrets! Wykonaj KROK 2 instrukcji.")
        return

    print("🍪 Używam ciasteczka sesyjnego (pomijam logowanie)...")

    session = requests.Session()
    # Udajemy przeglądarkę i wklejamy Twoje ciasteczko
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0 Safari/537.36",
        "Content-Type": "application/json",
        "Cookie": IRACING_COOKIE 
    })

    print("📡 Pobieranie listy sesji...")
    
    try:
        # Od razu strzelamy po dane
        r = session.get("https://members-ng.iracing.com/data/hosted/sessions")
    except Exception as e:
        send_discord(f"❌ Błąd połączenia: {e}")
        return

    # Obsługa błędów autoryzacji
    if r.status_code == 401 or r.status_code == 403:
        send_discord("⛔ Błąd 401/403: Twoje ciasteczko wygasło. Zaloguj się w przeglądarce i skopiuj nowe do GitHub Secrets.")
        return
    elif r.status_code != 200:
        send_discord(f"❌ Inny błąd API: {r.status_code} | {r.text[:200]}")
        return

    # Jeśli przeszło, to mamy dane!
    data = r.json()
    sessions = data.get("sessions", [])
    print(f"📊 Pobrana liczba sesji: {len(sessions)}")

    if not sessions:
        send_discord("ℹ️ Lista sesji jest pusta.")
        return

    # --- TESTOWE WYSYŁANIE 5 SESJI ---
    send_discord(f"🍪 **METODA CIASTECZKOWA DZIAŁA!** Widzę {len(sessions)} sesji. Przykłady:")

    for s in sessions[:5]:
        session_name = s.get('session_name', 'No Name')
        track = s.get('track', {}).get('track_name', 'Unknown Track')
        
        # Wyciąganie aut
        cars = s.get('cars', [])
        car_names = ", ".join([c.get('car_name', 'Car') for c in cars])
        if len(car_names) > 50: car_names = car_names[:50] + "..."

        status = "🔒" if s.get('password_protected') else "🔓"

        msg = (
            f"{status} **{session_name}**\n"
            f"📍 {track}\n"
            f"🏎️ {car_names}\n"
            "-----------------------"
        )
        send_discord(msg)

if __name__ == "__main__":
    check_hosted()
