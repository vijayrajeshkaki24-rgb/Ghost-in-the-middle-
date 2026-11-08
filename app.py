"""ACASE Flask API.  Run from repo root:  python -m backend.app"""
import uuid
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse

import secrets
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

from .ai_engine import recommend
from .config import Config
from .otp import OTPManager
from .report import build_pdf
from .scanner.engine import run_scan, validate_target
from .storage import Store


def create_app(cfg=Config):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = cfg.SECRET_KEY
    CORS(app, origins=cfg.CORS_ORIGINS)
    store, otp = Store(cfg.DATA_DIR), OTPManager(cfg)
    cfg.REPORT_DIR.mkdir(parents=True, exist_ok=True)

    def auth(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            info = store.key_info(request.headers.get("X-API-Key", ""))
            if not info:
                return jsonify(error="Missing or invalid API key."), 401
            request.acase_user = info
            return fn(*a, **kw)
        return wrapper

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", service="ACASE", version="1.0")

    @app.post("/api/register")
    def register():
        d = request.get_json(silent=True) or {}
        email, url = (d.get("email") or "").strip().lower(), (d.get("url") or "").strip()
        if "@" not in email:
            return jsonify(error="Valid email required."), 400
        try:
            validate_target(url)
        except ValueError as e:
            return jsonify(error=str(e)), 400
        otp.issue(email, urlparse(url).hostname)
        return jsonify(message=f"OTP sent (valid {cfg.OTP_VALIDITY_SECONDS}s).")

    @app.post("/api/verify")
    def verify():
        d = request.get_json(silent=True) or {}
        email = (d.get("email") or "").strip().lower()
        host = otp.verify(email, str(d.get("otp") or ""))
        if not host:
            return jsonify(error="Invalid or expired OTP."), 401
        key = secrets.token_hex(24)
        store.add_key(key, email, host)
        return jsonify(api_key=key, target_host=host)

    @app.post("/api/scan")
    @auth
    def scan():
        d = request.get_json(silent=True) or {}
        url = (d.get("url") or "").strip()
        try:
            validate_target(url)
        except ValueError as e:
            return jsonify(error=str(e)), 400
        user = request.acase_user
        if urlparse(url).hostname != user["host"]:
            return jsonify(error=f"This key is only authorised for {user['host']}."), 403
        try:
            result = run_scan(url, cfg)
        except Exception as e:  # network errors etc.
            return jsonify(error=f"Scan failed: {e}"), 502
        result["recommendations"] = recommend(result, cfg)
        result.update(id=uuid.uuid4().hex[:12], owner=user["email"],
                      created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        store.save_scan(result)
        return jsonify(result)

    def _owned(sid):
        s = store.get_scan(sid)
        return s if s and s["owner"] == request.acase_user["email"] else None

    @app.get("/api/scans")
    @auth
    def scans():
        rows = store.list_scans(request.acase_user["email"])
        return jsonify([{k: s[k] for k in ("id", "target", "band", "risk_score", "created_at")} for s in rows])

    @app.get("/api/scans/<sid>")
    @auth
    def one(sid):
        s = _owned(sid)
        return (jsonify(s), 200) if s else (jsonify(error="Not found."), 404)

    @app.get("/api/scans/<sid>/report")
    @auth
    def report(sid):
        s = _owned(sid)
        if not s:
            return jsonify(error="Not found."), 404
        path = cfg.REPORT_DIR / f"acase_{sid}.pdf"
        build_pdf(s, path)
        return send_file(path, mimetype="application/pdf", as_attachment=True, download_name=path.name)

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=Config.PORT)
