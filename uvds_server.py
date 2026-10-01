import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("UVDS_DB_PATH", ROOT / "uvds.sqlite3"))
PASSWORD_ITERATIONS = 600_000
SESSION_LIFETIME = 8 * 60 * 60
SESSIONS = {}


@contextmanager
def connect_database():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                middle_name TEXT NOT NULL DEFAULT '',
                last_name TEXT NOT NULL,
                mobile TEXT NOT NULL,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                address TEXT NOT NULL,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return f"{PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def password_matches(password, stored_hash):
    try:
        iterations, salt_hex, digest_hex = stored_hash.split("$")
        iterations = int(iterations)
        if not 1 <= iterations <= 2_000_000:
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), iterations
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return hmac.compare_digest(actual, expected)


class UVDSHandler(BaseHTTPRequestHandler):
    def send_json(self, status, payload, headers=()):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def session_user(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None
        session = cookie.get("uvds_session")
        if session is None:
            return None
        stored = SESSIONS.get(session.value)
        if stored is None:
            return None
        user_id, expires_at = stored
        if expires_at <= time.time():
            SESSIONS.pop(session.value, None)
            return None
        with connect_database() as connection:
            return connection.execute(
                "SELECT id, name, middle_name, last_name, email FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()

    @staticmethod
    def public_user(user):
        return {
            "name": " ".join(
                part for part in (user["name"], user["middle_name"], user["last_name"])
                if part
            ),
            "email": user["email"],
        }

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid request body") from exc
        if length <= 0 or length > 16_384:
            raise ValueError("Invalid request body")
        try:
            payload = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Invalid request body") from exc
        if not isinstance(payload, dict):
            raise ValueError("Invalid request body")
        return payload

    def do_GET(self):
        route = urlsplit(self.path).path
        if route == "/api/me":
            user = self.session_user()
            if user is None:
                self.send_json(401, {"error": "Not signed in."})
                return
            self.send_json(200, {"user": self.public_user(user)})
            return
        if route != "/":
            self.send_error(404)
            return
        page = (ROOT / "UVDS Login.html").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self):
        route = urlsplit(self.path).path
        if route == "/api/logout":
            self.logout()
            return
        try:
            payload = self.read_json()
            if route == "/api/register":
                self.register(payload)
            elif route == "/api/login":
                self.login(payload)
            else:
                self.send_json(404, {"error": "Endpoint not found"})
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})

    def register(self, payload):
        name = str(payload.get("name", "")).strip()
        middle_name = str(payload.get("middle_name", "")).strip()
        last_name = str(payload.get("last_name", "")).strip()
        mobile = str(payload.get("mobile", "")).strip()
        email = str(payload.get("email", "")).strip()
        address = str(payload.get("address", "")).strip()
        username = str(payload.get("username", "")).strip()
        password = payload.get("password", "")

        if not all((name, last_name, mobile, email, address, username)):
            raise ValueError("Please complete all required fields.")
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("Password must be at least 8 characters.")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise ValueError("Enter a valid email address.")

        try:
            with connect_database() as connection:
                connection.execute(
                    """INSERT INTO users
                       (name, middle_name, last_name, mobile, email, address,
                        username, password_hash)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        name,
                        middle_name,
                        last_name,
                        mobile,
                        email,
                        address,
                        username,
                        hash_password(password),
                    ),
                )
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "That email or username is already registered."})
            return
        self.send_json(201, {"message": "Registration successful."})

    def login(self, payload):
        username = str(payload.get("username", "")).strip()
        password = payload.get("password", "")
        if not username or not isinstance(password, str) or not password:
            raise ValueError("Enter your username and password.")
        with connect_database() as connection:
            user = connection.execute(
                "SELECT id, name, middle_name, last_name, email, password_hash "
                "FROM users WHERE username = ? COLLATE NOCASE",
                (username,),
            ).fetchone()
        if user is None or not password_matches(password, user["password_hash"]):
            self.send_json(401, {"error": "Invalid username or password."})
            return
        token = secrets.token_urlsafe(32)
        SESSIONS[token] = (user["id"], time.time() + SESSION_LIFETIME)
        cookie = (
            f"uvds_session={token}; HttpOnly; SameSite=Strict; Path=/; "
            f"Max-Age={SESSION_LIFETIME}"
        )
        self.send_json(
            200,
            {"message": "Login successful.", "user": self.public_user(user)},
            headers=(("Set-Cookie", cookie),),
        )

    def logout(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except CookieError:
            pass
        session = cookie.get("uvds_session")
        if session is not None:
            SESSIONS.pop(session.value, None)
        self.send_json(
            200,
            {"message": "Signed out."},
            headers=(("Set-Cookie", "uvds_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),),
        )


if __name__ == "__main__":
    host = os.environ.get("UVDS_HOST", "127.0.0.1")
    port = int(os.environ.get("UVDS_PORT", "8000"))
    server = ThreadingHTTPServer((host, port), UVDSHandler)
    print(f"UVDS login server running at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()