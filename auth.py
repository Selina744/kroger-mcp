"""Kroger OAuth2 AuthManager with token persistence and ephemeral callback listener."""

import base64
import json
import os
import sys
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import requests

# --- Configuration from environment variables ---

CLIENT_ID = os.environ.get("KROGER_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("KROGER_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("KROGER_REDIRECT_URI", "http://localhost:8080/callback")

BASE_URL = "https://api.kroger.com/v1"
AUTH_URL = "https://api.kroger.com/v1/connect/oauth2"

TOKEN_DIR = os.path.expanduser("~/.local/share/kroger-mcp")
TOKEN_FILE = os.path.join(TOKEN_DIR, "tokens.json")

SCOPES = "product.compact cart.basic:write"


class AuthManager:
    def __init__(self):
        self.client_id = CLIENT_ID
        self.client_secret = CLIENT_SECRET
        self.redirect_uri = REDIRECT_URI

        # App-level token (client credentials)
        self.app_access_token = None
        self.app_token_expires_at = 0

        # User-level token (authorization code flow)
        self.user_access_token = None
        self.user_refresh_token = None
        self.user_token_expires_at = 0

        self._load_tokens()

    def _basic_auth_header(self):
        credentials = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode()
        ).decode()
        return {"Authorization": f"Basic {credentials}"}

    # --- Token Persistence ---

    def _save_tokens(self):
        """Save user tokens to disk."""
        os.makedirs(TOKEN_DIR, exist_ok=True)
        data = {
            "user_access_token": self.user_access_token,
            "user_refresh_token": self.user_refresh_token,
            "user_token_expires_at": self.user_token_expires_at,
        }
        fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        print(f"Tokens saved to {TOKEN_FILE}", file=sys.stderr)

    def _load_tokens(self):
        """Load user tokens from disk if available."""
        if not os.path.exists(TOKEN_FILE):
            return
        try:
            with open(TOKEN_FILE) as f:
                data = json.load(f)
            self.user_access_token = data.get("user_access_token")
            self.user_refresh_token = data.get("user_refresh_token")
            self.user_token_expires_at = data.get("user_token_expires_at", 0)
            print("Loaded saved tokens from disk", file=sys.stderr)
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: could not load tokens: {e}", file=sys.stderr)

    # --- App Token (Client Credentials) ---

    def _fetch_app_token(self):
        """Fetch a new app-level access token via client credentials grant."""
        resp = requests.post(
            f"{AUTH_URL}/token",
            headers=self._basic_auth_header(),
            data={
                "grant_type": "client_credentials",
                "scope": SCOPES,
            },
        )
        resp.raise_for_status()
        token_data = resp.json()
        self.app_access_token = token_data["access_token"]
        self.app_token_expires_at = time.time() + token_data.get("expires_in", 1800)
        print("Fetched new app access token", file=sys.stderr)

    def get_app_token(self):
        """Return a valid app access token, refreshing if expired."""
        if not self.app_access_token or time.time() >= self.app_token_expires_at - 60:
            self._fetch_app_token()
        return self.app_access_token

    # --- User Token (Authorization Code Flow) ---

    def generate_authorize_url(self):
        """Build the Kroger OAuth authorization URL."""
        return (
            f"{AUTH_URL}/authorize"
            f"?scope={SCOPES.replace(' ', '%20')}"
            f"&response_type=code"
            f"&client_id={self.client_id}"
            f"&redirect_uri={self.redirect_uri}"
        )

    def exchange_code_for_token(self, code):
        """Exchange an authorization code for user access + refresh tokens."""
        resp = requests.post(
            f"{AUTH_URL}/token",
            headers=self._basic_auth_header(),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
            },
        )
        resp.raise_for_status()
        token_data = resp.json()
        self.user_access_token = token_data["access_token"]
        self.user_refresh_token = token_data["refresh_token"]
        self.user_token_expires_at = time.time() + token_data.get("expires_in", 1800)
        self._save_tokens()
        print("User tokens acquired and saved", file=sys.stderr)

    def refresh_user_token(self):
        """Refresh the user access token using the refresh token."""
        if not self.user_refresh_token:
            raise RuntimeError("No refresh token available. Please authorize first.")

        resp = requests.post(
            f"{AUTH_URL}/token",
            headers=self._basic_auth_header(),
            data={
                "grant_type": "refresh_token",
                "refresh_token": self.user_refresh_token,
            },
        )
        resp.raise_for_status()
        token_data = resp.json()
        self.user_access_token = token_data["access_token"]
        self.user_refresh_token = token_data["refresh_token"]
        self.user_token_expires_at = time.time() + token_data.get("expires_in", 1800)
        self._save_tokens()
        print("User tokens refreshed and saved", file=sys.stderr)

    def get_user_token(self):
        """Return a valid user access token, refreshing if needed."""
        if not self.user_access_token:
            return None
        if time.time() >= self.user_token_expires_at - 60:
            try:
                self.refresh_user_token()
            except Exception as e:
                print(f"Token refresh failed: {e}", file=sys.stderr)
                return None
        return self.user_access_token

    # --- Ephemeral Localhost Listener ---

    def authorize_interactive(self):
        """Run one-time interactive OAuth flow with an ephemeral localhost listener."""
        parsed = urlparse(self.redirect_uri)
        port = parsed.port or 8080
        callback_path = parsed.path or "/callback"

        captured_code = None

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                nonlocal captured_code
                query = parse_qs(urlparse(self.path).query)
                if "code" in query:
                    captured_code = query["code"][0]
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(
                        b"<html><body><h1>Authorization successful!</h1>"
                        b"<p>You can close this tab and return to the terminal.</p>"
                        b"</body></html>"
                    )
                else:
                    self.send_response(400)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(
                        b"<html><body><h1>Error</h1>"
                        b"<p>No authorization code received.</p>"
                        b"</body></html>"
                    )

            def log_message(self, format, *args):
                # Route HTTP server logs to stderr
                print(f"[callback server] {format % args}", file=sys.stderr)

        auth_url = self.generate_authorize_url()
        print(f"\nAuthorize your Kroger account by visiting:\n\n  {auth_url}\n", file=sys.stderr)

        try:
            webbrowser.open(auth_url)
            print("(Browser should open automatically)", file=sys.stderr)
        except Exception:
            print("(Could not open browser — please open the URL manually)", file=sys.stderr)

        server = HTTPServer(("127.0.0.1", port), CallbackHandler)
        print(f"Waiting for callback on port {port}...", file=sys.stderr)
        server.handle_request()  # Handle exactly one request
        server.server_close()

        if captured_code:
            print(f"Received authorization code, exchanging for tokens...", file=sys.stderr)
            self.exchange_code_for_token(captured_code)
            print("Authorization complete!", file=sys.stderr)
            return True
        else:
            print("No authorization code received.", file=sys.stderr)
            return False


if __name__ == "__main__":
    if not CLIENT_ID or not CLIENT_SECRET:
        print(
            "Error: KROGER_CLIENT_ID and KROGER_CLIENT_SECRET environment variables must be set.\n"
            "\n"
            "  export KROGER_CLIENT_ID=your_client_id\n"
            "  export KROGER_CLIENT_SECRET=your_client_secret\n"
            "  python auth.py\n",
            file=sys.stderr,
        )
        sys.exit(1)

    auth = AuthManager()
    success = auth.authorize_interactive()
    sys.exit(0 if success else 1)
