"""Gmail API and OAuth 2.0 Integration Service for SecureMailAnalyzer.
Handles OAuth 2.0 authorization, token exchange/refresh, message querying,
and zero-download attachment retrieval using official Google APIs.
"""

import base64
import json
import os
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from database import clear_gmail_token, create_oauth_state, get_active_gmail_token, save_gmail_token

# Google OAuth 2.0 Endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"

# Minimal required read-only scope
GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
]

CREDENTIALS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gmail_credentials.json")


def get_oauth_config() -> Dict[str, str]:
    """Retrieve OAuth client configuration from environment or credentials file."""
    client_id = os.environ.get("GMAIL_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GMAIL_CLIENT_SECRET", "").strip()
    redirect_uri = os.environ.get("GMAIL_REDIRECT_URI", "http://127.0.0.1:5000/api/gmail/callback").strip()

    if (not client_id or not client_secret) and os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                web_config = data.get("web") or data.get("installed") or data
                client_id = client_id or web_config.get("client_id", "")
                client_secret = client_secret or web_config.get("client_secret", "")
                redirects = web_config.get("redirect_uris", [])
                if redirects and not os.environ.get("GMAIL_REDIRECT_URI"):
                    redirect_uri = redirects[0]
        except Exception:
            pass

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
    }


def save_oauth_config(client_id: str, client_secret: str, redirect_uri: Optional[str] = None) -> None:
    """Save OAuth credentials to local config file."""
    config = {
        "client_id": client_id.strip(),
        "client_secret": client_secret.strip(),
        "redirect_uri": (redirect_uri or "http://127.0.0.1:5000/api/gmail/callback").strip(),
    }
    with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


def generate_auth_url(state: Optional[str] = None) -> Tuple[bool, str]:
    """Generate Google OAuth 2.0 authorization URL with cryptographically secure CSRF state."""
    cfg = get_oauth_config()
    if not cfg["client_id"] or not cfg["client_secret"]:
        return False, "Google OAuth Client ID and Secret are not configured. Please supply them in settings or environment."

    csrf_state = state or create_oauth_state()

    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "response_type": "code",
        "scope": " ".join(GMAIL_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": csrf_state,
    }
    auth_url = f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}"
    return True, auth_url


def exchange_code_for_tokens(code: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Exchange authorization code for access and refresh tokens."""
    cfg = get_oauth_config()
    if not cfg["client_id"] or not cfg["client_secret"]:
        return False, "Missing OAuth credentials.", None

    data = {
        "code": code,
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "redirect_uri": cfg["redirect_uri"],
        "grant_type": "authorization_code",
    }

    try:
        resp = requests.post(GOOGLE_TOKEN_URL, data=data, timeout=15)
        if resp.status_code != 200:
            err_data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            err_msg = err_data.get("error_description") or err_data.get("error") or resp.text
            return False, f"Token exchange failed: {err_msg}", None

        token_data = resp.json()
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in", 3600)
        scope = token_data.get("scope", "")

        expiry_iso = datetime.fromtimestamp(datetime.now().timestamp() + expires_in, timezone.utc).isoformat()

        # Fetch user profile to get connected email
        profile_res = requests.get(
            f"{GMAIL_API_BASE}/profile",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        if profile_res.status_code != 200:
            return False, "Failed to retrieve user Gmail profile.", None

        profile_data = profile_res.json()
        user_email = profile_data.get("emailAddress", "unknown@gmail.com")

        # Save to database
        save_gmail_token(
            email=user_email,
            access_token=access_token,
            refresh_token=refresh_token,
            token_expiry=expiry_iso,
            scope=scope,
        )

        return True, "Gmail connected successfully.", {
            "email": user_email,
            "connected_at": datetime.now(timezone.utc).isoformat(),
            "messages_total": profile_data.get("messagesTotal", 0),
        }
    except Exception as e:
        return False, f"Network or API error during token exchange: {str(e)}", None


def get_valid_access_token() -> Tuple[bool, Optional[str], Optional[str]]:
    """Retrieve active access token, refreshing it if expired."""
    session = get_active_gmail_token()
    if not session:
        return False, None, "No active Gmail connection found."

    access_token = session["access_token"]
    refresh_token = session.get("refresh_token")
    expiry_str = session.get("token_expiry")

    # Check if token is expired or close to expiry (within 60 seconds)
    is_expired = False
    if expiry_str:
        try:
            exp_dt = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
            if datetime.now(timezone.utc).timestamp() >= exp_dt.timestamp() - 60:
                is_expired = True
        except Exception:
            pass

    if not is_expired:
        return True, access_token, None

    # Needs refresh
    if not refresh_token:
        clear_gmail_token()
        return False, None, "Access token expired and no refresh token available. Please reconnect Gmail."

    cfg = get_oauth_config()
    if not cfg["client_id"] or not cfg["client_secret"]:
        return False, None, "Missing OAuth credentials to refresh token."

    try:
        resp = requests.post(
            GOOGLE_TOKEN_URL,
            data={
                "client_id": cfg["client_id"],
                "client_secret": cfg["client_secret"],
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
            timeout=15,
        )
        if resp.status_code != 200:
            clear_gmail_token()
            return False, None, "Failed to refresh token. Session revoked or expired."

        data = resp.json()
        new_access = data.get("access_token")
        new_expiry_in = data.get("expires_in", 3600)
        new_expiry_iso = datetime.fromtimestamp(datetime.now().timestamp() + new_expiry_in, timezone.utc).isoformat()

        save_gmail_token(
            email=session["email"],
            access_token=new_access,
            refresh_token=refresh_token,
            token_expiry=new_expiry_iso,
            scope=session.get("scope"),
        )
        return True, new_access, None
    except Exception as e:
        return False, None, f"Error refreshing Gmail token: {str(e)}"


def get_gmail_connection_status() -> Dict[str, Any]:
    """Return current Gmail connection status and configuration availability."""
    cfg = get_oauth_config()
    is_configured = bool(cfg["client_id"] and cfg["client_secret"])
    session = get_active_gmail_token()

    if not session:
        return {
            "connected": False,
            "email": None,
            "oauth_configured": is_configured,
            "client_id_prefix": cfg["client_id"][:12] + "..." if cfg["client_id"] else None,
            "redirect_uri": cfg["redirect_uri"],
            "status_label": "NOT_CONNECTED",
        }

    return {
        "connected": True,
        "email": session["email"],
        "connected_at": session["connected_at"],
        "oauth_configured": is_configured,
        "client_id_prefix": cfg["client_id"][:12] + "..." if cfg["client_id"] else None,
        "redirect_uri": cfg["redirect_uri"],
        "status_label": "ACTIVE",
    }


def list_messages_with_attachments(max_results: int = 20, query: str = "has:attachment") -> Tuple[bool, str, List[Dict[str, Any]]]:
    """Query Gmail for recent messages containing attachments."""
    ok, token, err = get_valid_access_token()
    if not ok:
        return False, err or "Gmail not connected", []

    try:
        url = f"{GMAIL_API_BASE}/messages"
        params = {"q": query, "maxResults": max_results}
        headers = {"Authorization": f"Bearer {token}"}

        resp = requests.get(url, params=params, headers=headers, timeout=15)
        if resp.status_code != 200:
            return False, f"Gmail API error: {resp.text[:120]}", []

        data = resp.json()
        messages_meta = data.get("messages", [])
        if not messages_meta:
            return True, "No messages with attachments found.", []

        # Fetch message headers for each
        results = []
        for item in messages_meta[:max_results]:
            msg_id = item["id"]
            msg_res = requests.get(
                f"{GMAIL_API_BASE}/messages/{msg_id}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date",
                headers=headers,
                timeout=10,
            )
            if msg_res.status_code == 200:
                m_data = msg_res.json()
                headers_list = m_data.get("payload", {}).get("headers", [])
                subject = "No Subject"
                sender = "Unknown Sender"
                date_str = ""
                for h in headers_list:
                    if h.get("name") == "Subject":
                        subject = h.get("value", subject)
                    elif h.get("name") == "From":
                        sender = h.get("value", sender)
                    elif h.get("name") == "Date":
                        date_str = h.get("value", date_str)

                results.append({
                    "id": msg_id,
                    "threadId": m_data.get("threadId"),
                    "subject": subject,
                    "from": sender,
                    "date": date_str,
                    "snippet": m_data.get("snippet", "")[:120],
                })

        return True, "Retrieved messages successfully", results
    except Exception as e:
        return False, f"Failed to list messages: {str(e)}", []


def get_message_attachments_metadata(message_id: str) -> Tuple[bool, str, Dict[str, Any]]:
    """Retrieve full message structure and identify all associated attachments."""
    ok, token, err = get_valid_access_token()
    if not ok:
        return False, err or "Gmail not connected", {}

    try:
        url = f"{GMAIL_API_BASE}/messages/{message_id}?format=full"
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            return False, f"Failed to retrieve message: {resp.text[:100]}", {}

        m_data = resp.json()
        headers_list = m_data.get("payload", {}).get("headers", [])
        subject = "No Subject"
        sender = "Unknown Sender"
        date_str = ""
        for h in headers_list:
            if h.get("name") == "Subject":
                subject = h.get("value", subject)
            elif h.get("name") == "From":
                sender = h.get("value", sender)
            elif h.get("name") == "Date":
                date_str = h.get("value", date_str)

        # Recursively parse MIME parts to locate all attachments
        attachments = []

        def extract_parts(parts):
            for part in parts:
                filename = part.get("filename", "").strip()
                body = part.get("body", {})
                att_id = body.get("attachmentId")
                part_id = part.get("partId", "")
                size = body.get("size", 0)

                if filename and (att_id or part_id):
                    attachments.append({
                        "attachment_id": att_id or f"part_{part_id}",
                        "part_id": part_id,
                        "filename": filename,
                        "mime_type": part.get("mimeType", "application/octet-stream"),
                        "size_bytes": size,
                    })
                # Check nested parts (multipart/mixed, multipart/alternative)
                if "parts" in part:
                    extract_parts(part["parts"])

        payload = m_data.get("payload", {})
        if "parts" in payload:
            extract_parts(payload["parts"])
        elif payload.get("filename") and (payload.get("body", {}).get("attachmentId") or payload.get("partId")):
            attachments.append({
                "attachment_id": payload.get("body", {}).get("attachmentId", ""),
                "part_id": payload.get("partId", ""),
                "filename": payload["filename"],
                "mime_type": payload.get("mimeType", "application/octet-stream"),
                "size_bytes": payload.get("body", {}).get("size", 0),
            })

        return True, "Message parsed", {
            "id": message_id,
            "subject": subject,
            "sender": sender,
            "date": date_str,
            "attachments": attachments,
            "attachment_count": len(attachments),
        }
    except Exception as e:
        return False, f"Error inspecting message attachments: {str(e)}", {}


def retrieve_attachment_bytes(message_id: str, attachment_id: str) -> Tuple[bool, str, Optional[bytes]]:
    """Retrieve raw attachment bytes directly from Gmail API in memory.
    Decodes URL-safe base64 data without saving to user disk or Downloads folder.
    """
    ok, token, err = get_valid_access_token()
    if not ok:
        return False, err or "Gmail not connected", None

    try:
        url = f"{GMAIL_API_BASE}/messages/{message_id}/attachments/{attachment_id}"
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(url, headers=headers, timeout=25)
        if resp.status_code != 200:
            return False, f"Gmail API attachment fetch error: {resp.text[:120]}", None

        data = resp.json()
        raw_b64 = data.get("data", "")
        if not raw_b64:
            return False, "Attachment payload data was empty.", None

        # Decode URL-safe base64
        file_bytes = base64.urlsafe_b64decode(raw_b64)
        return True, "Retrieved attachment bytes successfully in-memory.", file_bytes
    except Exception as e:
        return False, f"Failed to retrieve attachment bytes: {str(e)}", None
