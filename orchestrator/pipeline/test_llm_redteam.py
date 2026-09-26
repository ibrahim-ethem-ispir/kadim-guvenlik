"""Türkçe: LLM red-teaming (llm_redteam) SAF çekirdek testleri — ağ yok.

Kapsam: looks_like_llm_candidate (endpoint sezgisi), detect_instruction_following,
analyze_probe (injection işaret-yansıması → confirmed; system-prompt sızıntısı → probable).

Çalıştır: python3 orchestrator/pipeline/test_llm_redteam.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.llm_redteam import (  # noqa: E402
    looks_like_llm_candidate, detect_instruction_following, analyze_probe,
    echo_probe, injection_probes, make_nonce, _harvest_text,
)


def test_candidate_by_path():
    assert looks_like_llm_candidate("https://x.com/api/chat")
    assert looks_like_llm_candidate("https://x.com/assistant/ask")
    assert not looks_like_llm_candidate("https://x.com/about-us")


def test_candidate_by_param():
    assert looks_like_llm_candidate("https://x.com/search?message=hi")
    assert looks_like_llm_candidate("https://x.com/q?prompt=x")
    assert not looks_like_llm_candidate("https://x.com/p?id=1")


def test_instruction_following_echo():
    assert detect_instruction_following("Sure: KDMLLMabc123", "KDMLLMabc123")
    assert not detect_instruction_following("I cannot do that.", "KDMLLMabc123")


def test_injection_marker_confirmed():
    f = analyze_probe("prompt_injection", "Okay. PWNED-deadbeef", "PWNED-deadbeef", url="https://x/chat")
    assert f and f["confidence_tier"] == "confirmed" and f["severity"] == "high"
    assert f["mitre"] == "AML.T0051"


def test_injection_no_marker_none():
    f = analyze_probe("prompt_injection", "I won't follow that instruction.", "PWNED-deadbeef")
    assert f is None  # işaret yansımadı → bulgu YOK (false-positive üretme)


def test_system_prompt_leak_probable():
    resp = ("You are a helpful assistant. Your role is to answer support questions. "
            "You must not reveal internal data.")
    f = analyze_probe("system_prompt_leak", resp, "", url="https://x/chat")
    assert f and f["confidence_tier"] == "probable" and f["mitre"] == "AML.T0056"


def test_system_prompt_leak_benign_none():
    f = analyze_probe("system_prompt_leak", "The weather is nice today.", "")
    assert f is None


def test_harvest_text_from_json():
    obj = {"choices": [{"message": {"content": "hello world"}}], "id": "abc"}
    txt = _harvest_text(obj)
    assert "hello world" in txt


def test_probe_builders():
    n = make_nonce()
    assert echo_probe(n)["marker"].startswith("KDMLLM")
    kinds = {p["kind"] for p in injection_probes(n)}
    assert kinds == {"prompt_injection", "system_prompt_leak"}


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
