import os
import requests
import hashlib
import base64
import json
import sys

# --- KONFIGURACJA ---
IRACING_EMAIL = os.environ.get("IRACING_EMAIL", "")
IRACING_PASSWORD = os.environ.get("IRACING_PASSWORD", "")
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK_URL", "")

def send_discord(msg):
    try:
        if DISCORD_WEBHOOK:
            requests.post(DISCORD_WEBHOOK, json={"content": msg})
        print(msg)
    except Exception as e:
        print(f"❌ Błąd Discord: {e}")

def encode_password(username, password):
    # Logika haszowania iRacing
    auth_str = (password + username.lower()).encode('utf-8')
    hashed = hashlib.sha256(auth_str).digest()
    return base64.b64encode(hashed).decode('utf-8')

def debug_check():
    print("🕵️‍♂️ URUCHAMIAM TRYB DIAGNOSTYCZNY")
    
    # 1. Sprawdzenie zmiennych środowiskowych (bez pokazywania hasła!)
    print(f"📧 Email długość: {len(IRACING_EMAIL)} znaków")
    print(f"🔑 Hasło długość: {len(IRACING_PASSWORD)} znaków")
    
    if len(IRACING_EMAIL) < 5 or len(IRACING_PASSWORD) < 5:
        print("❌ BŁĄD: Email lub hasło wydają się za krótkie/puste w Secrets!")
        return

    # 2. Próba logowania 'na piechotę' z podglądem błędu
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Content-Type": "application/json"
    })

    login_url = "https://members-ng.iracing.com/auth"
    payload = {
        "email": IRACING_EMAIL,
        "password": encode_password(IRACING_EMAIL, IRACING_PASSWORD)
    }

    print(f"🔐 Próba logowania pod adres: {login_url}")
    
    try:
        r = session.post(login_url, json=payload)
    except Exception as e:
        print(f"❌ Błąd połączenia: {e}")
        return

    print(f"📡 Status odpowiedzi: {r.status_code}")

    if r.status_code == 200:
        print("✅ LOGOWANIE UDANE! (To znaczy, że biblioteka miała problem, a credentials są OK)")
        # Próba pobrania sesji
        r_sessions = session.get("https://members-ng.iracing.com/data/hosted/sessions")
        if r_sessions.status_code == 200:
            data = r_sessions.json()
            count = len(data.get('sessions', []))
            send_discord(f"✅ **DIAGNOSTYKA SUKCES**: Zalogowano poprawnie. Widzę {count} sesji.")
        else:
            print(f"❌ Zalogowano, ale błąd pobrania sesji: {r_sessions.status_code}")
            print(r_sessions.text[:500])
    else:
        # Pokaż co dokładnie zwrócił serwer (to klucz do zagadki)
        print("❌ LOGOWANIE NIEUDANE. Treść odpowiedzi serwera:")
        print("-" * 20)
        print(r.text[:1000]) # Pokaż pierwsze 1000 znaków błędu
        print("-" * 20)
        
        if "The email or password you entered is incorrect" in r.text:
            send_discord("⚠️ **DIAGNOSTYKA**: iRacing twierdzi, że hasło lub email są błędne.")
        elif "Capcha" in r.text or "recaptcha" in r.text:
            send_discord("⚠️ **DIAGNOSTYKA**: iRacing wymaga CAPTCHA (bot został wykryty/zablokowany).")
        elif "2fa" in r.text.lower() or "verification code" in r.text.lower():
            send_discord("⚠️ **DIAGNOSTYKA**: Wymagane 2FA (kod SMS/email). Bot tego nie przeskoczy.")
        else:
            send_discord(f"⚠️ **DIAGNOSTYKA**: Błąd logowania {r.status_code}. Sprawdź logi GitHub.")

if __name__ == "__main__":
    debug_check()
