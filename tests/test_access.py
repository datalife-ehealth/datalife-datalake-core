import pytest

from services.access_control import AccessController


def test_otp_expires_and_rejects_the_wrong_subject():
    clock = {"now": 1_700_000_000.0}
    controller = AccessController("test-secret", {"PHY-0001"}, clock=lambda: clock["now"])
    grant = controller.issue_otp("subj-1", "PHY-0001", ttl_seconds=60)
    assert controller.validate_otp(grant.token, "subj-1")
    assert controller.validate_otp(grant.token, "subj-2") is False
    clock["now"] += 61
    assert controller.validate_otp(grant.token, "subj-1") is False


def test_glass_break_requires_a_master_physician_id():
    controller = AccessController("test-secret", {"PHY-0001"}, clock=lambda: 10.0)
    with pytest.raises(PermissionError):
        controller.glass_break("PHY-9999", "subj-1", "unconscious")
    grant = controller.glass_break("PHY-0001", "subj-1", "unconscious")
    assert grant.kind == "GLASS_BREAK"
    assert grant.subject_key == "subj-1"
