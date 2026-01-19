#!/usr/bin/env python3
import os
import sys
import json
import textwrap
from typing import Any, Dict, List, Optional

import requests


IR_OAUTH_TOKEN_URL = "https://oauth.iracing.com/oauth2/token"
IR_DATA_BASE_URL = "https://members-ng.iracing.com/data"
HOSTED_SESSIONS_ENDPOINT = f"{IR_DATA_BASE_URL}/hosted/sessions"
# Alternatywnie:
# HOSTED_SESSIONS_ENDPOINT = f"{IR_DATA_BASE_URL}/hosted/combined_sessions"


def get_env_var(name: str) -> str:
    value = os.getenv(name)
    if not value:
        print(f"Missing required environment variable: {name}", file=sys.stderr)
        sys.exit(1)
    return value


def get_access_token(
    client_id: str,
    client_secret: str,
    email: str,
    password: str,
    audience: str = "data-server",
) -> str:
    """
    Uzyskanie access tokena z /token przy użyciu Password Limited Grant.
    Dokumentacja: /token endpoint + Password Limited Flow
    """
    data = {
        "grant_type": "password_limited",
        "client_id": client_id,
        "client_secret": client_secret,
        "username": email,
        "password": password,
        "audience": audience,
        # scope można zostawić puste lub dodać np. "data:read" jeśli wymagane
        # "scope": "data:read",
    }

    resp = requests.post(IR_OAUTH_TOKEN_URL, data=data, timeout=15)
    if not resp.ok:
        print(
            f"Failed to obtain access token: {resp.status_code} {resp.text}",
            file=sys.stderr,
        )
        sys.exit(1)

    token_payload = resp.json()
    access_token = token_payload.get("access_token")
    if not access_token:
        print("No access_token in token response", file=sys.stderr)
        sys.exit(1)

    return access_token


def fetch_iracing_data_link(url: str, access_token: str) -> Dict[str, Any]:
    """
    Pierwsze wywołanie /data endpointu – zwraca JSON z linkiem do właściwego pliku.
    Wzorzec opisany w dokumentacji /data API.
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
    }
    resp = requests.get(url, headers=headers, timeout=15)
    if not resp.ok:
        print(
            f"Failed to call data endpoint: {resp.status_code} {resp.text}",
            file=sys.stderr,
        )
        sys.exit(1)

    return resp.json()


def download_iracing_data_file(link: str, access_token: str) -> Any:
    """
    Drugie wywołanie – pobranie właściwego pliku z danymi (JSON) z linku zwróconego
    przez pierwszy request do /data endpointu.
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
    }
    resp = requests.get(link, headers=headers, timeout=30)
    if not resp.ok:
        print(
            f"Failed to download data file: {resp.status_code} {resp.text}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Zwykle to JSON, ale bywa też CSV – tu zakładamy JSON dla hosted sessions.
    try:
        return resp.json()
    except json.JSONDecodeError:
        print("Downloaded data is not valid JSON", file=sys.stderr)
        sys.exit(1)


def get_hosted_sessions(access_token: str) -> List[Dict[str, Any]]:
    """
    Pobiera listę hosted sessions z /data/hosted/sessions.
    Zwraca listę słowników reprezentujących sesje.
    """
    meta = fetch_iracing_data_link(HOSTED_SESSIONS_ENDPOINT, access_token)
    link = meta.get("link")
    if not link:
        print("No 'link' field in hosted sessions response", file=sys.stderr)
        sys.exit(1)

    data = download_iracing_data_file(link, access_token)

    # Struktura może się zmieniać – często jest to lista lub obiekt z kluczem 'sessions'
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Spróbujmy kilku typowych kluczy
        for key in ("sessions", "data", "hosted_sessions"):
            if key in data and isinstance(data[key], list):
                return data[key]

    print("Unexpected hosted sessions data structure", file=sys.stderr)
    print(json.dumps(data, indent=2))
    sys.exit(1)


def format_session(session: Dict[str, Any]) -> str:
    """
    Przyjazne formatowanie pojedynczej sesji do wysłania na Discorda.
    Pola mogą się różnić – tu kilka typowych, z bezpiecznym .get().
    """
    name = session.get("session_name") or session.get("name") or "Unnamed session"
    track = session.get("track", {}).get("track_name") or session.get("track_name") or "Unknown track"
    car = session.get("car", {}).get("car_name") or session.get("car_name") or "Unknown car"
    start_time = session.get("start_time") or session.get("launch_at") or "Unknown start"
    session_id = session.get("session_id") or session.get("id") or "N/A"

    lines = [
        f"**{name}**",
        f"- Session ID: `{session_id}`",
        f"- Track: {track}",
        f"- Car: {car}",
        f"- Start: {start_time}",
    ]
    return "\n".join(lines)


def build_discord_message(sessions: List[Dict[str, Any]], limit: int = 5) -> str:
    """
    Buduje treść wiadomości na Discorda z pierwszych N sesji.
    """
    if not sessions:
        return "Brak dostępnych hosted sessions w tej chwili."

    selected = sessions[:limit]
    parts = [format_session(s) for s in selected]
    body = "\n\n".join(parts)

    header = f"Znaleziono {len(sessions)} hosted sessions. Oto pierwsze {len(selected)}:"
    return f"{header}\n\n{body}"


def send_to_discord(webhook_url: str, content: str) -> None:
    """
    Wysyła prostą wiadomość tekstową na Discord webhook.
    """
    payload = {
        "content": content,
    }
    resp = requests.post(webhook_url, json=payload, timeout=15)
    if not resp.ok:
        print(
            f"Failed to send message to Discord: {resp.status_code} {resp.text}",
            file=sys.stderr,
        )
        sys.exit(1)


def main() -> None:
    # Pobranie konfiguracji z env (ustawianych przez GitHub Secrets)
    discord_webhook = get_env_var("DISCORD_WEBHOOK")
    client_id = get_env_var("IR_CLIENT_ID")
    client_secret = get_env_var("IR_CLIENT_SECRET")
    ir_email = get_env_var("IR_EMAIL")
    ir_password = get_env_var("IR_PASSWORD")

    print("Requesting iRacing access token...")
    access_token = get_access_token(
        client_id=client_id,
        client_secret=client_secret,
        email=ir_email,
        password=ir_password,
    )

    print("Fetching hosted sessions...")
    sessions = get_hosted_sessions(access_token)

    print(f"Total sessions found: {len(sessions)}")
    message = build_discord_message(sessions, limit=5)

    # Discord ma limit długości wiadomości – przy bardzo dużej liczbie sesji
    # można by dodać dodatkowe przycięcie, ale 5 pierwszych to bezpieczny zakres.
    if len(message) > 1900:
        message = message[:1900] + "\n\n...(przycięto)..."

    print("Sending message to Discord...")
    send_to_discord(discord_webhook, message)
    print("Done.")


if __name__ == "__main__":
    main()
