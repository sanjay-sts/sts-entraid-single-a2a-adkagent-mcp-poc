"""Development configuration loader for auth bypass.

Reads dev_config.toml (gitignored) to control auth bypass per server.
If the file doesn't exist, all auth is enforced (production behavior).
"""
import logging
import tomllib
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).parent / "dev_config.toml"
_config: dict[str, Any] | None = None
_logged_sections: set[str] = set()


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
