"""Security tests for ABAC attribute handling.

Verifies that claim-only ABAC attributes cannot be spoofed via the
X-Abac-Attrs header. Specifically, `department` must always come from
the validated JWT claim and never from the per-request header, since
the header is set client-side and could otherwise be used to escalate
privileges across departments.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from dev_config import parse_abac_attrs


class TestHeaderBlockedAbacKeys:
    """X-Abac-Attrs header MUST NOT override claim-only attributes."""

    def test_department_in_header_is_stripped(self):
        """A user passing `department` in X-Abac-Attrs should have it stripped."""
        result = parse_abac_attrs('{"department": "Finance"}')
        assert "department" not in result, (
            "department must not propagate from X-Abac-Attrs header; "
            "it is claim-only to prevent cross-dept privilege escalation"
        )

    def test_department_stripped_but_other_attrs_kept(self):
        """Blocking department should not affect other header attrs (e.g. archiver)."""
        result = parse_abac_attrs('{"department": "HR", "archiver": true}')
        assert "department" not in result
        assert result.get("archiver") is True, (
            "archiver is header-driven (frontend toggle); must be preserved"
        )

    def test_archiver_only_passes_through(self):
        """archiver alone (no department) passes through unchanged."""
        result = parse_abac_attrs('{"archiver": true}')
        assert result == {"archiver": True}

    def test_empty_header_returns_empty(self):
        """Empty/missing header still returns empty dict (existing behavior)."""
        assert parse_abac_attrs("") == {}
        assert parse_abac_attrs(None) == {}

    def test_invalid_json_returns_empty(self):
        """Invalid JSON returns empty dict (existing behavior)."""
        assert parse_abac_attrs("not valid json") == {}

    def test_department_stripped_even_with_unrelated_keys(self):
        """Other future ABAC attrs should still pass through, only department is blocked."""
        result = parse_abac_attrs('{"department": "HR", "archiver": true, "team": "platform"}')
        assert "department" not in result
        assert result.get("archiver") is True
        assert result.get("team") == "platform"
