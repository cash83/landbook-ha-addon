"""Helpers for safe log output."""
from __future__ import annotations


def mask_value(value, visible: int = 4) -> str:
    s = str(value or "").strip()
    if not s:
        return ""
    if len(s) <= 2:
        return "***"
    if len(s) <= visible * 2:
        return f"{s[0]}***{s[-1]}"
    return f"{s[:visible]}...{s[-visible:]}"
