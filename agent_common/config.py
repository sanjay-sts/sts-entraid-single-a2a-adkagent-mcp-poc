"""Shared configuration readers.

Only the *parsing* lives here. Each service still performs its own blocklist
check against its own module-level copy, and that duplication is deliberate:
an agent that trusted an upstream hop to have checked would be trusting a hop
it cannot see. What is being removed is three hand-rolled copies of the same
split-and-strip, which is where a subtle difference — one service trimming
whitespace and another not — would go unnoticed.
"""
import os


def load_blocked_users() -> list[str]:
    """User ids denied at every tier, from the `BLOCKED_USERS` env var.

    Comma-separated, whitespace tolerant, empty entries dropped. That last
    part matters: callers test `claims.get("sub", "")` against this list, so a
    stray trailing comma would put `""` in it and block every token whose
    subject claim is absent. It denies rather than admits, so it is not a
    hole — but a trailing comma in a `.env` producing a tenant-wide outage is
    worth one `if`.
    """
    return [u.strip() for u in os.getenv("BLOCKED_USERS", "").split(",") if u.strip()]
