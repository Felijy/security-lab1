import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import click
import jwt
from flask import Flask, current_app, g, jsonify, request
from markupsafe import escape
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

MAX_PASSWORD_LENGTH = 128
AUTH_SCHEME = "Bearer"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    content TEXT NOT NULL
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        JWT_SECRET_KEY=os.environ.get("JWT_SECRET_KEY"),
        DATABASE=os.environ.get("DATABASE_PATH", str(Path(app.instance_path) / "lab.sqlite3")),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    secret = app.config["JWT_SECRET_KEY"]
    if not isinstance(secret, str) or len(secret.encode()) < 32:
        raise RuntimeError("Set JWT_SECRET_KEY to a random secret of at least 32 bytes")
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    dummy_hash = generate_password_hash(secrets.token_urlsafe(32), method="scrypt")

    @app.teardown_appcontext
    def close_db(_error):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        response = error.get_response()
        response.data = app.json.dumps({"error": error.name})
        response.content_type = "application/json"
        return response

    def unauthorized():
        return jsonify(error="Invalid credentials or token"), 401, {"WWW-Authenticate": AUTH_SCHEME}

    def protected(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            parts = request.headers.get("Authorization", "").split()
            if len(parts) != 2 or parts[0].lower() != AUTH_SCHEME.lower():
                return unauthorized()
            try:
                claims = jwt.decode(
                    parts[1], secret, algorithms=["HS256"],
                    issuer="security-lab1", audience="security-lab1-api",
                    options={"require": ["sub", "exp", "iat", "iss", "aud"]},
                )
            except jwt.InvalidTokenError:
                return unauthorized()
            user = get_db().execute("SELECT id FROM users WHERE username = ?", (claims["sub"],)).fetchone()
            if user is None:
                return unauthorized()
            g.user_id = user["id"]
            return view(*args, **kwargs)
        return wrapped

    def json_fields(fields):
        data = request.get_json()
        if not isinstance(data, dict) or set(data) != set(fields):
            return None
        for key, limit in fields.items():
            value = data[key]
            if not isinstance(value, str) or not value.strip() or len(value) > limit or "\x00" in value:
                return None
        return data

    @app.post("/auth/login")
    def login():
        data = json_fields({"username": 64, "password": MAX_PASSWORD_LENGTH})
        if data is None:
            return jsonify(error="Expected username and password strings"), 400
        user = get_db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?", (data["username"],)
        ).fetchone()
        valid = check_password_hash(user["password_hash"] if user else dummy_hash, data["password"])
        if user is None or not valid:
            return unauthorized()
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {"sub": user["username"], "iat": now, "exp": now + timedelta(minutes=15),
             "iss": "security-lab1", "aud": "security-lab1-api"},
            secret, algorithm="HS256",
        )
        return jsonify(access_token=token, token_type=AUTH_SCHEME, expires_in=900)

    def serialize_note(row):
        return {"id": row["id"], "title": str(escape(row["title"])), "content": str(escape(row["content"]))}

    @app.get("/api/data")
    @protected
    def list_notes():
        rows = get_db().execute(
            "SELECT id, title, content FROM notes WHERE owner_id = ? ORDER BY id", (g.user_id,)
        ).fetchall()
        return jsonify(data=[serialize_note(row) for row in rows])

    @app.post("/api/notes")
    @protected
    def create_note():
        data = json_fields({"title": 200, "content": 2000})
        if data is None:
            return jsonify(error="Expected title (1-200) and content (1-2000) strings"), 400
        db = get_db()
        with db:
            cursor = db.execute(
                "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
                (g.user_id, data["title"], data["content"]),
            )
        return jsonify(serialize_note({"id": cursor.lastrowid, **data})), 201

    @app.cli.command("init-db")
    def init_db():
        with get_db() as db:
            db.executescript(SCHEMA)
        click.echo("Database initialized.")

    @app.cli.command("create-user")
    @click.option("--username", prompt=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    def create_user(username, password):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
            raise click.ClickException("Username: 3-64 ASCII letters, digits, _, . or -")
        if not 12 <= len(password) <= MAX_PASSWORD_LENGTH:
            raise click.ClickException("Password must contain 12-128 characters")
        try:
            with get_db() as db:
                db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                           (username, generate_password_hash(password, method="scrypt")))
        except sqlite3.IntegrityError as error:
            raise click.ClickException("Username already exists") from error
        click.echo("User created.")

    return app
