"""Development configuration loader for auth bypass.

Reads dev_config.toml (gitignored) to control auth bypass per server.
If the file doesn't exist, all auth is enforced (production behavior).
Config is cached at first load — restart servers after changes.
"""
import json
import logging
import tomllib
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent
PERMISSIONS_PATH = PROJECT_ROOT / "permissions.toml"
CEDAR_DIR = PROJECT_ROOT / "cedar"

_CONFIG_PATH = PROJECT_ROOT / "dev_config.toml"
_config: dict[str, Any] | None = None
_logged_sections: set[str] = set()

# Sentinel token used when auth is bypassed in dev mode
DEV_BYPASS_TOKEN = "dev-bypass-token"


def _load_config() -> dict[str, Any]:
    global _config
    if _config is not None:
        return _config
    if _CONFIG_PATH.exists():
        with open(_CONFIG_PATH, "rb") as f:
            _config = tomllib.load(f)
    else:
        _config = {}
    return _config


def is_auth_disabled(section: str) -> bool:
    """Check if auth is disabled for the given server section."""
    config = _load_config()
    disabled = config.get(section, {}).get("disable_auth", False)
    if section not in _logged_sections:
        _logged_sections.add(section)
        if disabled:
            logger.warning(
                "\n========================================\n"
                "  ⚠️  AUTH BYPASS ENABLED for: %s\n"
                "  Config: %s\n"
                "========================================",
                section.upper(),
                _CONFIG_PATH,
            )
        else:
            logger.info("[%s] Auth enforced (disable_auth=false)", section.upper())
    return disabled


def get_section(section: str) -> dict[str, Any]:
    """Get the full config section for a server."""
    return _load_config().get(section, {})


# Claim-only ABAC keys: NEVER accepted from the X-Abac-Attrs header.
# These attributes must come exclusively from validated JWT claims so the
# client cannot spoof them (e.g. cross-department privilege escalation).
HEADER_BLOCKED_ABAC_KEYS = frozenset({"department"})


def parse_abac_attrs(raw: str) -> dict:
    """Parse a JSON string of ABAC attributes into a dict.

    Used by A2A and MCP servers to decode the X-Abac-Attrs header. Keys
    listed in HEADER_BLOCKED_ABAC_KEYS are stripped — those attributes
    are claim-only and must not be settable via the header.

    Returns empty dict on missing/invalid input. Unknown keys (other than
    the blocked set) are harmlessly ignored — only keys in ABAC_CLAIM_KEYS
    are extracted during Cedar entity building.
    """
    if not raw:
        return {}
    try:
        attrs = json.loads(raw)
        if not isinstance(attrs, dict):
            return {}
        return {k: v for k, v in attrs.items() if k not in HEADER_BLOCKED_ABAC_KEYS}
    except (json.JSONDecodeError, TypeError):
        logger.warning("Invalid ABAC attrs JSON: %.100s", raw)
        return {}


def detect_provider(claims: dict) -> str:
    """Detect IdP from token issuer claim.

    Shared across A2A and MCP servers to avoid duplication.
    """
    iss = claims.get("iss", "")
    if "login.microsoftonline.com" in iss or "sts.windows.net" in iss:
        return "entra"
    if "cognito-idp" in iss:
        return "cognito"
    if "auth0.com" in iss:
        return "auth0"
    return "unknown"
