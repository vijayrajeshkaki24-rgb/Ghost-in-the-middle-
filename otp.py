"""Email OTP used to verify the requester before any scan is allowed."""
import hashlib
import hmac
import secrets
import smtplib
import time
from email.message import EmailMessage


class OTPManager:
    def __init__(self, cfg):
        self.cfg = cfg
        self.pending = {}  # email -> dict

    @staticmethod
    def _h(v): return hashlib.sha256(v.encode()).hexdigest()

    def issue(self, email: str, host: str) -> str:
        code = f"{secrets.randbelow(10**6):06d}"
        self.pending[email] = {"h": self._h(code), "exp": time.time() + self.cfg.OTP_VALIDITY_SECONDS,
                               "tries": 0, "host": host}
        self._send(email, code)
        return code

    def verify(self, email: str, code: str):
        rec = self.pending.get(email)
        if not rec or time.time() > rec["exp"] or rec["tries"] >= self.cfg.OTP_MAX_ATTEMPTS:
            self.pending.pop(email, None)
            return None
        rec["tries"] += 1
        if hmac.compare_digest(rec["h"], self._h(code or "")):
            self.pending.pop(email, None)
            return rec["host"]
        return None

    def _send(self, email: str, code: str):
        c = self.cfg
        if not (c.SMTP_HOST and c.SMTP_USER):
            print(f"[ACASE][DEV] SMTP not configured. OTP for {email}: {code}", flush=True)
            return
        msg = EmailMessage()
        msg["Subject"] = "ACASE OTP Verification"
        msg["From"], msg["To"] = c.SMTP_USER, email
        msg.set_content(f"Your ACASE OTP is {code}. It is valid for {c.OTP_VALIDITY_SECONDS // 60} minutes. "
                        "Only scan systems you own or are authorised to test.")
        with smtplib.SMTP(c.SMTP_HOST, c.SMTP_PORT, timeout=15) as s:
            s.starttls()
            s.login(c.SMTP_USER, c.SMTP_PASSWORD)
            s.send_message(msg)
