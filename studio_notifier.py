import os
import requests
import sys
from typing import List, Optional, Dict

# Stałe konfiguracyjne
TOKEN_URL = "https://oauth.iracing.com/oauth2/token"
DATA_API_BASE = "https://data-server.iracing.com/data"
HOSTED_SESSIONS_ENDPOINT = f"{DATA_API_BASE}/hosted/sessions"

class IRacingClient:
    def __init__(self):
        self.client_id = os.getenv('IR_CLIENT_ID')
        self.client_secret = os.getenv('IR_CLIENT_SECRET')
        self.username = os.getenv('IR_EMAIL')
        self.password = os.getenv('IR_PASSWORD')
        self.webhook_url = os.getenv('DISCORD_WEBHOOK')
        self.access_token: Optional[str] = None

    def authenticate(self):
        """Uwierzytelnianie przy użyciu Password Limited Flow (RFC 6749 + iRacing spec)"""
        print("Inicjalizacja uwierzytelniania...")
        
        payload = {
            'grant_type': 'password_limited',
            'username': self.username,
            'password': self.password,
            'audience': 'data-server'
        }
        
        try:
            # Używamy Basic Auth (Client ID i Secret) zgodnie z dokumentacją token_endpoint
            response = requests.post(
                TOKEN_URL,
                data=payload,
                auth=(self.client_id, self.client_secret),
                timeout=15
            )
            
            if response.status_code != 200:
                print(f"Błąd uwierzytelniania: {response.status_code}")
                print(f"Odpowiedź serwera: {response.text}")
                sys.exit(1)
            
            data = response.json()
            self.access_token = data.get('access_token')
            print("Pomyślnie uzyskano token dostępu.")
            
        except requests.exceptions.RequestException as e:
            print(f"Błąd sieciowy podczas autoryzacji: {e}")
            sys.exit(1)

    def get_data(self, url: str) -> Optional[Dict]:
        """Pobiera dane z API uwzględniając mechanizm 'link' (S3 redirection)"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        try:
            # Krok 1: Pobranie adresu URL do danych
            print(f"Zapytywanie o dane: {url}")
            res = requests.get(url, headers=headers, timeout=15)
            
            if res.status_code == 204: # No Content
                return None
            
            res.raise_for_status()
            data_info = res.json()
            
            # Krok 2: Pobranie faktycznego JSONa z otrzymanego linku
            direct_link = data_info.get('link')
            if not direct_link:
                return data_info
            
            print("Pobieranie szczegółowych danych z linku zewnętrznego...")
            final_res = requests.get(direct_link, timeout=15)
            final_res.raise_for_status()
            return final_res.json()
            
        except Exception as e:
            print(f"Błąd podczas pobierania danych: {e}")
            return None

    def format_and_send_discord(self, sessions_data: Optional[Dict]):
        """Wysyła sformatowane informacje o 5 sesjach na Discorda"""
        if not sessions_data or 'sessions' not in sessions_data:
            content = "❌ Nie znaleziono obecnie aktywnych sesji Hosted."
        else:
            sessions = sessions_data['sessions']
            # Bierzemy maksymalnie 5 pierwszych sesji
            top_5 = sessions[:5]
            
            content = "🏎️ **iRacing Hosted Sessions Report**\n"
            content += "--------------------------------------------\n"
            
            for s in top_5:
                name = s.get('session_name', 'Unnamed Session')
                track = s.get('track', {}).get('track_name', 'Unknown Track')
                host = s.get('host_display_name', 'Unknown Host')
                count = s.get('num_registered', 0)
                max_u = s.get('max_users', 0)
                
                content += (f"🔹 **{name}**\n"
                            f"   • Tor: `{track}`\n"
                            f"   • Host: `{host}`\n"
                            f"   • Kierowcy: `{count}/{max_u}`\n\n")
            
            content += "--------------------------------------------"

        try:
            res = requests.post(self.webhook_url, json={"content": content}, timeout=10)
            res.raise_for_status()
            print("Powiadomienie wysłane do Discorda.")
        except Exception as e:
            print(f"Błąd wysyłki na Discord: {e}")

def main():
    # Walidacja zmiennych środowiskowych
    required = ['IR_CLIENT_ID', 'IR_CLIENT_SECRET', 'IR_EMAIL', 'IR_PASSWORD', 'DISCORD_WEBHOOK']
    missing = [r for r in required if not os.getenv(r)]
    if missing:
        print(f"Błąd: Brakujące sekrety: {', '.join(missing)}")
        sys.exit(1)

    client = IRacingClient()
    client.authenticate()
    
    # Pobieramy sesje Hosted
    data = client.get_data(HOSTED_SESSIONS_ENDPOINT)
    client.format_and_send_discord(data)

if __name__ == "__main__":
    main()
