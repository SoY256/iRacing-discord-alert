import os
import requests
import sys

# --- KONFIGURACJA ---
# Tutaj wklej swój User-Agent skopiowany z przeglądarki:
MY_BROWSER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:146.0) Gecko/20100101 Firefox/146.0" 
# np.: MY_BROWSER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

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
    global IRACING_COOKIE
    
    if not IRACING_COOKIE:
        print("❌ BŁĄD: Brak zmiennej IRACING_COOKIE w Secrets!")
        return

    # --- AUTO-NAPRAWA CIASTECZKA ---
    # Jeśli przez przypadek skopiowałeś "Cookie: " na początku, usuwamy to
    if IRACING_COOKIE.strip().lower().startswith("cookie:"):
        print("🔧 Wykryto prefiks 'Cookie:', naprawiam format...")
        IRACING_COOKIE = IRACING_COOKIE.split(":", 1)[1].strip()

    print(f"🍪 Ciasteczko załadowane (długość: {len(IRACING_COOKIE)} znaków)")
    
    # Jeśli użytkownik zapomniał podmienić User-Agent w kodzie, używamy domyślnego
    if "WKLEJ_TUTAJ" in MY_BROWSER_AGENT:
        print("⚠️ UWAGA: Nie podmieniłeś MY_BROWSER_AGENT w kodzie! Używam domyślnego (może nie działać).")
        agent_to_use = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0 Safari/537.36"
    else:
        print("🕵️ Używam Twojego User-Agent z przeglądarki.")
        agent_to_use = MY_BROWSER_AGENT

    session = requests.Session()
    session.headers.update({
        "User-Agent": agent_to_use,
        "Content-Type": "application/json",
        "Cookie": IRACING_COOKIE 
    })

    print("📡 Pobieranie listy sesji...")
    
    try:
        r = session.get("https://members-ng.iracing.com/data/hosted/sessions")
    except Exception as e:
        send_discord(f"❌ Błąd połączenia: {e}")
        return

    # Rozdzielamy błędy dla lepszej diagnozy
    if r.status_code == 401:
        send_discord("⛔ Błąd 401 (Unauthorized): Ciasteczko jest nieprawidłowe lub wygasło. Serwer go nie akceptuje.")
        print(r.text[:500])
    elif r.status_code == 403:
        send_discord("⛔ Błąd 403 (Forbidden): Cloudflare blokuje połączenie. Prawdopodobnie IP GitHuba jest na czarnej liście.")
    elif r.status_code != 200:
        send_discord(f"❌ Błąd API: {r.status_code} | {r.text[:200]}")
    else:
        # SUKCES!
        data = r.json()
        sessions = data.get("sessions", [])
        
        # Jeśli lista pusta, to też sukces (połączenie działa, tylko brak sesji)
        info_msg = f"✅ **SUKCES!** Połączono z iRacing. Liczba sesji online: {len(sessions)}"
        send_discord(info_msg)
        
        # Wyświetlamy 3 przykładowe dla pewności
        for s in sessions[:3]:
            name = s.get('session_name', 'Sesja')
            track = s.get('track', {}).get('track_name', 'Tor')
            print(f"-> {name} @ {track}")

if __name__ == "__main__":
    check_hosted()
