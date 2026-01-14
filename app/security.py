from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Iterable

import requests
from zxcvbn import zxcvbn

DEFAULT_ROCKYOU_PATH = Path(__file__).resolve().parent.parent / "data" / "rockyou.txt"

COMMON_PATTERNS = [
    r"^12345",
    r"password",
    r"qwerty",
    r"admin",
    r"letmein",
]

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789"]


def load_common_passwords(rockyou_path: str | Path | None = None) -> set[str]:
    rockyou_location = rockyou_path or os.getenv("ROCKYOU_PATH", str(DEFAULT_ROCKYOU_PATH))
    rockyou_path = Path(rockyou_location).expanduser()
    if not rockyou_path.exists():
        return set()
    return {
        line.strip().lower()
        for line in rockyou_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    }


def validate_password_input(password: str) -> tuple[bool, str | None]:
    if not isinstance(password, str):
        return False, "Password must be a string."
    if not password:
        return False, "Password is required."
    if len(password) > 128:
        return False, "Password is too long (max 128 characters)."
    return True, None


def has_sequence(password: str, sequence: str, min_len: int = 4) -> bool:
    lowered = password.lower()
    seq_len = len(sequence)
    for start in range(seq_len - min_len + 1):
        for end in range(start + min_len, seq_len + 1):
            chunk = sequence[start:end]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def has_keyboard_pattern(password: str, min_len: int = 4) -> bool:
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for start in range(len(row) - min_len + 1):
            chunk = row[start : start + min_len]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def rule_checks(password: str) -> tuple[list[str], list[str]]:
    tips: list[str] = []
    warnings: list[str] = []

    if len(password) < 12:
        tips.append("Use at least 12 characters.")

    if not re.search(r"[a-z]", password):
        tips.append("Add lowercase letters.")
    if not re.search(r"[A-Z]", password):
        tips.append("Add uppercase letters.")
    if not re.search(r"\d", password):
        tips.append("Add numbers.")
    if not re.search(r"[^A-Za-z0-9]", password):
        tips.append("Add symbols (like !@#).")

    lowered = password.lower()
    if any(re.search(pattern, lowered) for pattern in COMMON_PATTERNS):
        warnings.append("Avoid common patterns like 'password', 'qwerty', or '12345'.")

    if re.search(r"(.)\1\1", password):
        warnings.append("Avoid repeated characters like 'aaa' or '111'.")

    if any(has_sequence(password, sequence) for sequence in SEQUENCES):
        warnings.append("Avoid sequential patterns like 'abcd' or '6543'.")

    if has_keyboard_pattern(password):
        warnings.append("Avoid keyboard patterns like 'qwerty' or 'asdf'.")

    return tips, warnings


def evaluate_password(password: str, common_passwords: Iterable[str]) -> dict:
    analysis = zxcvbn(password)
    feedback = list(analysis.get("feedback", {}).get("suggestions", []))
    warnings = []

    zxcvbn_warning = analysis.get("feedback", {}).get("warning")
    if zxcvbn_warning:
        warnings.append(zxcvbn_warning)

    rule_feedback, rule_warnings = rule_checks(password)
    feedback.extend(rule_feedback)
    warnings.extend(rule_warnings)

    score = int(analysis.get("score", 0))
    if score <= 1:
        label = "WEAK"
    elif score <= 3:
        label = "OKAY"
    else:
        label = "STRONG"

    common_password = password.lower() in common_passwords
    common_password_source = "rockyou" if common_password else None
    if common_password:
        warnings.append(
            "This password appears in real-world breach lists (RockYou)."
        )

    return {
        "score": score,
        "label": label,
        "feedback": feedback,
        "warnings": warnings,
        "commonPassword": common_password,
        "commonPasswordSource": common_password_source,
        "breached": None,
        "crackTimeEstimates": analysis.get("crack_times_display", {}),
    }


def check_breached_password(password: str) -> bool | None:
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5,
        )
    except requests.RequestException:
        return None

    if response.status_code != 200:
        return None

    for line in response.text.splitlines():
        found_suffix, _count = line.split(":")
        if found_suffix == suffix:
            return True
    return False
