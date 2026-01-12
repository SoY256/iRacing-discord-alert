import os
import requests
import hashlib
import base64
import json
import sys

# --- DANE ---
IRACING_EMAIL = os.environ.get("IRACING_EMAIL", "")
IRACING_PASSWORD = os.environ.get("IRACING_PASSWORD", "")
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK_URL", "")

def send_discord(msg):
    try:
        if DISCORD_WEBHOOK:
            requests.post(DISCORD_WEBHOOK, json={"content": msg})
        print(msg)
    except:
        pass

def encode_password(username, password):
    auth_str = (password + username.lower()).encode('utf-8')
    hashed = hashlib.sha256(auth_str).digest()
    return base64.b64encode(hashed).decode('utf-8')

def check_hosted():
    print("🤖 START: Próba obejścia zabezpieczeń Cloudflare...")

    # UDAJEMY PRZEGLĄDARKĘ CHROME NA WINDOWSIE
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Origin": "https://members-ng.iracing.com",
        "Referer": "https://members-ng.iracing.com/jforum/forums/list.page"
    }

    session = requests.Session()
    session.headers.update(headers)

    # Haszowanie hasła
    try:
        hashed_pw = encode_password(IRACING_EMAIL, IRACING_PASSWORD)
    except Exception as e:
        send_discord(f"❌ Błąd kodowania hasła: {e}")
        return

    payload = {"email": IRACING_EMAIL, "password": hashed_pw}

    # PRÓBA LOGOWANIA
    print("🔐 Wysyłam login do iRacing...")
    
    try:
        # Uwaga: Nie używamy raise_for_status, żeby zobaczyć treść błędu
        r = session.post("https://members-ng.iracing.com/auth", json=payload)
    except Exception as e:
        send_discord(f"❌ Błąd połączenia sieciowego: {e}")
        return

    print(f"📡 Status odpowiedzi: {r.status_code}")

    # ANALIZA WYNIKU
    if r.status_code == 200:
        print("✅ ZALOGOWANO! Ominięto blokadę.")
        
        # Pobieramy sesje
        r_sess = session.get("https://members-ng.iracing.com/data/hosted/sessions")
        if r_sess.status_code == 200:
            data = r_sess.json()
            sessions = data.get('sessions', [])
            send_discord(f"🎉 SUKCES: Widzę {len(sessions)} sesji online. System działa.")
            
            # Tu (opcjonalnie) wklej pętlę filtrującą z poprzednich wersji, jeśli to zadziała
        else:
            send_discord(f"⚠️ Zalogowano, ale nie można pobrać sesji (Status {r_sess.status_code})")
            
    elif r.status_code == 405:
        print("⛔ BLOKADA 405 (Method Not Allowed).")
        print("To oznacza, że iRacing/Cloudflare blokuje Twoje IP (GitHub).")
        send_discord("❌ Błąd 405: iRacing blokuje logowanie z serwerów GitHuba.")

    elif r.status_code == 429:
        send_discord("⏳ Za dużo zapytań (Rate Limit). Odczekaj chwilę.")

    else:
        # Sprawdzamy czy to Cloudflare / Captcha
        content = r.text.lower()
        if "captcha" in content or "challenge" in content or "cloudflare" in content:
            print("🛡️ Wykryto CAPTCHA / Cloudflare.")
            send_discord("❌ Błąd: iRacing wymaga weryfikacji CAPTCHA (blokada anty-bot).")
        elif "incorrect" in content:
            send_discord("❌ Błąd: Nieprawidłowe hasło lub email.")
        else:
            # Wypisz początek błędu
            clean_err = r.text[:200].replace("\n", " ")
            send_discord(f"❌ Nieznany błąd logowania {r.status_code}: {clean_err}")

if __name__ == "__main__":
    check_hosted()
