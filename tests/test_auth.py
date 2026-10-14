import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

PASSWORD = "drosa-parole-1"


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "test.db"


@pytest.fixture
def client(db_path):
    return TestClient(create_app(db_path))


def register(client, email="lietotajs@example.com", password=PASSWORD, confirm=None):
    return client.post(
        "/auth/register",
        json={"email": email, "password": password, "passwordConfirm": confirm or password},
    )


def test_register_stores_user_with_bcrypt_hash(client, db_path):
    response = register(client)

    assert response.status_code == 201
    assert response.json()["email"] == "lietotajs@example.com"
    row = sqlite3.connect(db_path).execute("SELECT password_hash FROM users").fetchone()
    assert row[0].startswith("$2b$")
    assert PASSWORD not in row[0]


@pytest.mark.parametrize(
    ("email", "password", "confirm", "field", "issue"),
    [
        ("nav-epasts", PASSWORD, PASSWORD, "email", "INVALID_FORMAT"),
        ("a@example.com", "isa", "isa", "password", "TOO_SHORT"),
        ("a@example.com", "x" * 73, "x" * 73, "password", "TOO_LONG"),
        ("a@example.com", PASSWORD, PASSWORD + "x", "passwordConfirm", "DOES_NOT_MATCH"),
    ],
)
def test_register_rejects_invalid_input(client, email, password, confirm, field, issue):
    response = register(client, email, password, confirm)

    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert {"field": field, "issue": issue} in error["details"]


def test_register_missing_field_returns_400(client):
    response = client.post("/auth/register", json={"email": "a@example.com"})

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_register_duplicate_email_is_case_insensitive(client):
    register(client)

    response = register(client, email="Lietotajs@Example.com")

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "EMAIL_TAKEN"


def test_login_sets_httponly_session_cookie(client):
    register(client)

    response = client.post("/auth/login", json={"email": "lietotajs@example.com", "password": PASSWORD})

    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert cookie.startswith("session=")
    assert "HttpOnly" in cookie


@pytest.mark.parametrize("email", ["lietotajs@example.com", "nav@example.com"])
def test_login_with_wrong_credentials_returns_401(client, email):
    register(client)

    response = client.post("/auth/login", json={"email": email, "password": "nepareiza-parole"})

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INVALID_CREDENTIALS"


def test_protected_endpoint_requires_login(client):
    assert client.get("/auth/me").status_code == 401

    register(client)
    client.post("/auth/login", json={"email": "lietotajs@example.com", "password": PASSWORD})

    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.json()["email"] == "lietotajs@example.com"


def test_session_token_is_not_stored_in_plain_text(client, db_path):
    register(client)
    client.post("/auth/login", json={"email": "lietotajs@example.com", "password": PASSWORD})

    token = client.cookies["session"]
    stored = sqlite3.connect(db_path).execute("SELECT token_hash FROM sessions").fetchone()[0]
    assert stored != token


def test_logout_ends_session(client):
    register(client)
    client.post("/auth/login", json={"email": "lietotajs@example.com", "password": PASSWORD})
    token = client.cookies["session"]

    assert client.post("/auth/logout").status_code == 204

    client.cookies.set("session", token)
    assert client.get("/auth/me").status_code == 401


def test_home_page_redirects_anonymous_user_to_login(client):
    response = client.get("/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


@pytest.mark.parametrize("path", ["/login", "/register"])
def test_form_pages_are_served(client, path):
    response = client.get(path)

    assert response.status_code == 200
    assert "<form" in response.text


def test_unknown_path_uses_error_schema(client):
    response = client.get("/nav-tada")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"
