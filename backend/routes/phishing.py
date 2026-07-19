"""
RAKSHA -- Phishing Awareness Demo endpoint.

Receives submissions from the local fake "SecureTrust Bank" login page
(frontend/public/phishing_demo/bank-login.html) used to demonstrate
phishing simulation + detection inside the dashboard.

This endpoint does NOT authenticate anyone and does NOT represent a real
banking system. It exists purely so the RAKSHA scenario/audit-log/dashboard
can show what happens when a "victim" submits credentials to a simulated
phishing page -- the same signal a real detection pipeline would react to.

Security notes (intentional, and worth calling out in your demo):
- Captured data lives in memory only and is cleared on server restart.
- Passwords are never stored or logged in plaintext -- only a masked form
  is kept, to model good handling practice even inside a training tool.
"""

import time
from typing import List

from fastapi import APIRouter
from pydantic import BaseModel

from scenario import engine

router = APIRouter()

# In-memory store for this demo session only. Not persisted to disk.
_captures: List[dict] = []


class PhishingSubmission(BaseModel):
    customerId: str
    password: str
    timestamp: str
    page: str


def _mask_secret(value: str) -> str:
    """Never keep raw passwords around, even in a local demo."""
    if not value:
        return ""
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]


@router.post("/api/phishing-demo")
def capture_phishing_demo(submission: PhishingSubmission):
    """
    Records a simulated phishing-page submission and drops a
    hash-chained entry into the same audit log the rest of the
    dashboard reads from, so the capture is visible in the UI in
    real time.
    """
    record = {
        "customerId": submission.customerId,
        "password_masked": _mask_secret(submission.password),
        "page": submission.page,
        "client_timestamp": submission.timestamp,
        "received_at": time.time(),
    }
    _captures.append(record)

    engine._append_audit(
        "phishing_capture",
        f"Simulated phishing capture on '{submission.page}': "
        f"customerId='{submission.customerId}', "
        f"password='{record['password_masked']}' "
        f"(demo data only -- not a real account).",
    )

    return {"status": "captured", "total_captures": len(_captures)}


@router.get("/api/phishing-demo/captures")
def list_phishing_captures():
    """Lets a dashboard panel list everything captured this session."""
    return {"captures": _captures, "total": len(_captures)}


@router.post("/api/phishing-demo/reset")
def reset_phishing_captures():
    _captures.clear()
    return {"status": "reset"}