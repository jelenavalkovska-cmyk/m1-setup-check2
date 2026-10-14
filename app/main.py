"""Ezermalas pieteikumu sistēma · reģistrācija un pieteikšanās (CR-4 prototips).

Palaišana: uvicorn app.main:create_app --factory --port 8000
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

import bcrypt
from fastapi import Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException

from app.db import SESSION_LIFETIME, Database, EmailTaken

VERSION = "0.2.0"
SESSION_COOKIE = "session"
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_BYTES = 72  # bcrypt ņem vērā tikai pirmos 72 baitus
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PAGES = Path(__file__).parent / "pages"
# Lai atbildes laiks neatklātu, vai e-pasts ir reģistrēts.
DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt())

logger = logging.getLogger("app")


class RegisterRequest(BaseModel):
    email: str
    password: str
    passwordConfirm: str


class LoginRequest(BaseModel):
    email: str
    password: str


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details: list | None = None):
        self.status, self.code, self.message, self.details = status, code, message, details


def error_response(status: int, code: str, message: str, details: list | None = None):
    error: dict = {"code": code, "message": message}
    if details:
        error["details"] = details
    return JSONResponse({"error": error}, status_code=status)


def user_json(user) -> dict:
    return {"id": user["id"], "email": user["email"], "createdAt": user["created_at"]}


def normalize_email(email: str) -> str:
    return email.strip().lower()


def validate_registration(body: RegisterRequest) -> list[dict]:
    details = []
    if not EMAIL_PATTERN.fullmatch(normalize_email(body.email)):
        details.append({"field": "email", "issue": "INVALID_FORMAT"})
    if len(body.password) < PASSWORD_MIN_LENGTH:
        details.append({"field": "password", "issue": "TOO_SHORT"})
    elif len(body.password.encode()) > PASSWORD_MAX_BYTES:
        details.append({"field": "password", "issue": "TOO_LONG"})
    if body.password != body.passwordConfirm:
        details.append({"field": "passwordConfirm", "issue": "DOES_NOT_MATCH"})
    return details


def create_app(db_path: str | Path | None = None) -> FastAPI:
    db = Database(db_path or os.environ.get("APP_DB_PATH", "data/app.db"))
    cookie_secure = os.environ.get("COOKIE_SECURE", "0") == "1"

    app = FastAPI(title="Ezermalas pieteikumu sistēma", version=VERSION)

    @app.exception_handler(ApiError)
    async def handle_api_error(request: Request, exc: ApiError):
        return error_response(exc.status, exc.code, exc.message, exc.details)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(request: Request, exc: RequestValidationError):
        details = [
            {"field": str(err["loc"][-1]), "issue": "REQUIRED" if err["type"] == "missing" else "INVALID_FORMAT"}
            for err in exc.errors()
        ]
        return error_response(400, "VALIDATION_ERROR", "Request validation failed", details)

    @app.exception_handler(HTTPException)
    async def handle_http_error(request: Request, exc: HTTPException):
        if exc.status_code == 404:
            return error_response(404, "NOT_FOUND", "Resource not found")
        return error_response(exc.status_code, "BAD_REQUEST", str(exc.detail))

    @app.exception_handler(Exception)
    async def handle_internal_error(request: Request, exc: Exception):
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        return error_response(500, "INTERNAL_ERROR", "Internal server error")

    def current_user(request: Request):
        token = request.cookies.get(SESSION_COOKIE)
        user = db.get_session_user(token) if token else None
        if user is None:
            raise ApiError(401, "UNAUTHORIZED", "Authentication required")
        return user

    # --- API ---

    @app.get("/health", tags=["Sistēma"])
    def health():
        return {"status": "ok", "version": VERSION}

    @app.post("/auth/register", status_code=201, tags=["Autentifikācija"])
    def register(body: RegisterRequest):
        details = validate_registration(body)
        if details:
            raise ApiError(400, "VALIDATION_ERROR", "Request validation failed", details)
        password_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
        try:
            user = db.create_user(normalize_email(body.email), password_hash)
        except EmailTaken:
            raise ApiError(409, "EMAIL_TAKEN", "Email is already registered")
        logger.info("User registered: id=%s", user["id"])
        return user_json(user)

    @app.post("/auth/login", tags=["Autentifikācija"])
    def login(body: LoginRequest, response: Response):
        user = db.get_user_by_email(normalize_email(body.email))
        password = body.password.encode()[:PASSWORD_MAX_BYTES]
        stored_hash = user["password_hash"].encode() if user else DUMMY_HASH
        if not bcrypt.checkpw(password, stored_hash) or user is None:
            logger.warning("Failed login attempt")
            raise ApiError(401, "INVALID_CREDENTIALS", "Invalid email or password")
        token = db.create_session(user["id"])
        response.set_cookie(
            SESSION_COOKIE,
            token,
            max_age=int(SESSION_LIFETIME.total_seconds()),
            httponly=True,
            samesite="lax",
            secure=cookie_secure,
        )
        return user_json(user)

    @app.post("/auth/logout", status_code=204, tags=["Autentifikācija"])
    def logout(request: Request, user=Depends(current_user)):
        db.delete_session(request.cookies[SESSION_COOKIE])
        response = Response(status_code=204)
        response.delete_cookie(SESSION_COOKIE, httponly=True, samesite="lax", secure=cookie_secure)
        return response

    @app.get("/auth/me", tags=["Autentifikācija"])
    def me(user=Depends(current_user)):
        return user_json(user)

    # --- Lapas (nav API līguma daļa) ---

    def page(name: str) -> HTMLResponse:
        return HTMLResponse((PAGES / name).read_text(encoding="utf-8"))

    @app.get("/", include_in_schema=False)
    def home_page(request: Request):
        token = request.cookies.get(SESSION_COOKIE)
        if not token or db.get_session_user(token) is None:
            return RedirectResponse("/login", status_code=303)
        return page("home.html")

    @app.get("/login", include_in_schema=False)
    def login_page():
        return page("login.html")

    @app.get("/register", include_in_schema=False)
    def register_page():
        return page("register.html")

    return app
