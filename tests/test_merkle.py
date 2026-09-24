from services.crypto import merkle_root, seal, verify_chain


def test_merkle_root_is_deterministic_and_detects_mutation():
    records = [{"kind": "dicom", "object_key": "abc"}, {"kind": "xml", "object_key": "def"}]
    assert merkle_root(records) == merkle_root(list(records))
    first = seal(records, "0" * 64, 0)
    second = seal([{"type": "OTP_ISSUED", "subject_key": "subj-1"}], first["block_hash"], 1)
    assert verify_chain([first, second])
    first["records"][0]["object_key"] = "tampered"
    assert verify_chain([first, second]) is False


def test_empty_ledger_verifies():
    assert verify_chain([])
