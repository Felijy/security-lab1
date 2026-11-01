import secrets
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from werkzeug.security import check_password_hash

from app import create_app, get_db


@pytest.fixture
def app(tmp_path):
    application = create_app({
        "TESTING": True, "DATABASE": str(tmp_path / "test.sqlite3"),
        "JWT_SECRET_KEY": secrets.token_urlsafe(48),
    })
    runner = application.test_cli_runner()
    assert runner.invoke(args=["init-db"]).exit_code == 0
    for username in ("alice", "bob"):
        result = runner.invoke(args=["create-user", "--username", username,
                                     "--password", "A-test-password-2026!"])
        assert result.exit_code == 0, result.output
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def login(client, username="alice"):
    return client.post("/auth/login", json={"username": username, "password": "A-test-password-2026!"})


def auth(client, username="alice"):
    return {"Authorization": "Bearer " + login(client, username).json["access_token"]}


def signed(app, **changes):
    now = datetime.now(timezone.utc)
    payload = {"sub": "alice", "iat": now, "exp": now + timedelta(minutes=15),
               "iss": "security-lab1", "aud": "security-lab1-api"}
    payload.update(changes)
    return jwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")


def test_full_flow_and_owner_isolation(client):
    response = login(client)
    assert response.status_code == 200
    assert response.json["expires_in"] == 900
    alice = {"Authorization": "Bearer " + response.json["access_token"]}
    created = client.post("/api/notes", headers=alice, json={"title": "Lab", "content": "Hello"})
    assert created.status_code == 201
    assert client.get("/api/data", headers=alice).json["data"] == [created.json]
    assert client.get("/api/data", headers=auth(client, "bob")).json["data"] == []


@pytest.mark.parametrize("path,method", [("/api/data", "get"), ("/api/notes", "post")])
@pytest.mark.parametrize("header", [None, "Bearer", "Basic abc", "Bearer garbage", "Bearer a b"])
def test_protected_endpoints_require_valid_bearer(client, path, method, header):
    response = getattr(client, method)(path, headers={} if header is None else {"Authorization": header})
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize("changes", [
    {"exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
    {"nbf": datetime.now(timezone.utc) + timedelta(hours=1)},
    {"iss": "attacker"}, {"aud": "other-api"}, {"sub": "999"},
    {"sub": "1 OR 1=1"}, {"sub": "9" * 100}, {"sub": "²"},
])
def test_invalid_claims(app, client, changes):
    response = client.get("/api/data", headers={"Authorization": "Bearer " + signed(app, **changes)})
    assert response.status_code == 401


@pytest.mark.parametrize("claim", ["sub", "exp", "iat", "iss", "aud"])
def test_missing_required_claim(app, client, claim):
    payload = jwt.decode(signed(app), app.config["JWT_SECRET_KEY"], algorithms=["HS256"],
                         audience="security-lab1-api")
    del payload[claim]
    token = jwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")
    assert client.get("/api/data", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_forged_and_unsigned_tokens(app, client):
    payload = jwt.decode(signed(app), app.config["JWT_SECRET_KEY"], algorithms=["HS256"],
                         audience="security-lab1-api")
    tokens = [jwt.encode(payload, secrets.token_urlsafe(48), algorithm="HS256"),
              jwt.encode(payload, "", algorithm="none"),
              jwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS384")]
    for token in tokens:
        assert client.get("/api/data", headers={"Authorization": "Bearer " + token}).status_code == 401


@pytest.mark.parametrize("username,password", [
    ("alice", "wrong"), ("nobody", "wrong"), ("' OR 1=1 --", "anything"),
    ("alice' --", "anything"), ("alice", "' OR '1'='1"),
])
def test_bad_credentials_and_sqli(client, username, password):
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 401
    assert response.json["error"] == "Invalid credentials or token"


def test_sqli_in_note_is_literal(client):
    headers = auth(client)
    payload = {"title": "'); DROP TABLE users; --", "content": "' OR 1=1 --"}
    assert client.post("/api/notes", headers=headers, json=payload).status_code == 201
    assert login(client).status_code == 200
    assert len(client.get("/api/data", headers=headers).json["data"]) == 1


def test_xss_escaped_on_creation_and_read(client):
    headers = auth(client)
    response = client.post("/api/notes", headers=headers,
                           json={"title": '<script>alert("x")</script>', "content": "<img src=x onerror=alert(1)> & '"})
    assert response.status_code == 201
    assert "<" not in response.json["title"]
    assert response.json["title"] == "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;"
    assert "&lt;img" in response.json["content"]
    assert "&amp;" in response.json["content"]
    assert client.get("/api/data", headers=headers).json["data"] == [response.json]


@pytest.mark.parametrize("payload", [[], None, {}, {"username": "alice"},
    {"username": 123, "password": "a"}, {"username": "a", "password": []},
    {"username": " ", "password": "a"}, {"username": "a", "password": "a" * 129},
    {"username": "alice", "password": "a", "admin": True}])
def test_login_validation(client, payload):
    assert client.post("/auth/login", json=payload).status_code in (400, 415)


@pytest.mark.parametrize("payload", [{}, [], {"title": "x", "content": 2},
    {"title": "x" * 201, "content": "x"}, {"title": "x", "content": "x" * 2001},
    {"title": " ", "content": "x"}, {"title": "x", "content": "a\x00b"},
    {"title": "x", "content": "x", "owner_id": 2}])
def test_note_validation(client, payload):
    assert client.post("/api/notes", headers=auth(client), json=payload).status_code == 400


def test_password_hash_and_cli(app):
    with app.test_request_context():
        hashed = get_db().execute("SELECT password_hash FROM users WHERE username = ?", ("alice",)).fetchone()[0]
        assert hashed.startswith("scrypt:")
        assert check_password_hash(hashed, "A-test-password-2026!")
        bob_hash = get_db().execute("SELECT password_hash FROM users WHERE username = ?", ("bob",)).fetchone()[0]
        assert hashed != bob_hash
    runner = app.test_cli_runner()
    for username, password in [("alice", "long-enough-password"), ("a", "long-enough-password"), ("newuser", "short")]:
        assert runner.invoke(args=["create-user", "--username", username, "--password", password]).exit_code != 0


def test_deleted_account_token_rejected(client, app):
    headers = auth(client)
    with app.test_request_context():
        db = get_db()
        with db:
            db.execute("DELETE FROM users WHERE username = ?", ("alice",))
    assert client.get("/api/data", headers=headers).status_code == 401


@pytest.mark.parametrize("secret", [None, "", "short"])
def test_missing_or_short_secret_rejected(tmp_path, secret):
    with pytest.raises(RuntimeError, match="JWT_SECRET_KEY"):
        create_app({"JWT_SECRET_KEY": secret, "DATABASE": str(tmp_path / "unused.sqlite3")})


def test_errors_and_security_headers(client):
    responses = [client.get("/api/data"), client.get("/missing"), client.get("/auth/login"),
                 client.post("/auth/login", data="not-json", content_type="text/plain"),
                 client.post("/auth/login", data="{", content_type="application/json"),
                 client.post("/auth/login", data="x" * 17000, content_type="application/json")]
    assert [r.status_code for r in responses] == [401, 404, 405, 415, 400, 413]
    for response in responses:
        assert response.content_type == "application/json"
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert "POST" in responses[2].headers["Allow"]
