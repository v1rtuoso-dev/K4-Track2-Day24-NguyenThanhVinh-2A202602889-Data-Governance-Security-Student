"""Đo precision/recall của agent.pii trên tests/vn_pii_testset.jsonl.

    pytest tests/test_pii.py -v -s

Rubric (RUBRIC.md): >95% = 10đ, 85-95% = 7đ, <85% = 3đ (đo trên recall).
Test này chỉ FAIL cứng nếu recall quá thấp (coi như chưa implement) —
điểm số theo band do người chấm đọc số in ra, không phải pass/fail nhị phân.
"""
from __future__ import annotations

import json
from pathlib import Path

from agent import pii

TESTSET_PATH = Path(__file__).resolve().parent / "vn_pii_testset.jsonl"


def _load_testset() -> list[dict]:
    with TESTSET_PATH.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _overlaps(a: dict, b: dict) -> bool:
    return a["type"] == b["type"] and a["start"] < b["end"] and b["start"] < a["end"]


def test_pii_detection_precision_recall():
    testset = _load_testset()
    assert testset, "vn_pii_testset.jsonl trống hoặc thiếu file"

    total_gold = 0
    total_pred = 0
    true_positive = 0

    for row in testset:
        gold = row["entities"]
        pred = pii.detect(row["text"])
        total_gold += len(gold)
        total_pred += len(pred)
        matched_gold = set()
        for p in pred:
            for i, g in enumerate(gold):
                if i not in matched_gold and _overlaps(p, g):
                    matched_gold.add(i)
                    true_positive += 1
                    break

    precision = true_positive / total_pred if total_pred else 0.0
    recall = true_positive / total_gold if total_gold else 0.0

    print(f"\n[pii] gold={total_gold} pred={total_pred} tp={true_positive}")
    print(f"[pii] precision={precision:.3f} recall={recall:.3f}")

    assert recall >= 0.5, (
        f"recall={recall:.3f} quá thấp — kiểm tra lại regex trong agent/pii.py "
        "(xem CHECKPOINTS.md (§3a))"
    )


def test_redact_removes_detected_entities():
    text = "CCCD của khách là 012345678912, SĐT 0912345678."
    detected = pii.detect(text)
    redacted = pii.redact(text)
    assert redacted != text or not detected
    for entity in detected:
        original_value = text[entity["start"] : entity["end"]]
        assert original_value not in redacted, f"redact() vẫn còn lộ {original_value!r}"


def test_exact_spans_overlap_and_reverse_redaction():
    text = ("Liên hệ: CCCD 012345678912; STK: 012345678901; "
            "số tài khoản 0912345678; SĐT 0912-345-678; email a.b+lab@example.vn.")
    values = [
        ("VN_CCCD", "012345678912"),
        ("VN_BANK_ACCOUNT", "012345678901"),
        ("VN_BANK_ACCOUNT", "0912345678"),
        ("VN_PHONE", "0912-345-678"),
        ("EMAIL", "a.b+lab@example.vn"),
    ]
    entities = pii.detect(text)
    assert entities == [
        {"type": kind, "start": text.index(value), "end": text.index(value) + len(value)}
        for kind, value in values
    ]
    assert [(e["type"], text[e["start"]:e["end"]]) for e in entities] == values
    assert pii.redact(text) == (
        "Liên hệ: CCCD [REDACTED_VN_CCCD]; STK: [REDACTED_VN_BANK_ACCOUNT]; "
        "số tài khoản [REDACTED_VN_BANK_ACCOUNT]; SĐT [REDACTED_VN_PHONE]; "
        "email [REDACTED_EMAIL].")


def test_no_numeric_fragments_inside_longer_values():
    assert pii.detect("Mã 12345678901234567; 0912345678901; KH-000999.") == []
