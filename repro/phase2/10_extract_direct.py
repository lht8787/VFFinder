#!/usr/bin/env python3
"""Giai doan 2 - Buoc 2.1: baseline 'Direct' (khong vi du) - trich Attack Vector (AV) va Root Cause (RC)
tu mo ta CVE bang Gemini, THEO TUNG CAU (giong repo: nltk.sent_tokenize), roi gop ket qua cac cau.

Prompt bam sat repo (VFFinder/.../splitPrompt.py) nhung BO phan vi du (dung nhu paper mo ta cho baseline
'LLM without demonstration'). Co them 1 dong chi dan dinh dang JSON de parse on dinh (tat bang --no-format-hint).

Chay: python 10_extract_direct.py --data repro/phase1/data --out repro/phase2/data
"""
import argparse, csv, json, os, pathlib, re, sys

ap = argparse.ArgumentParser()
ap.add_argument("--data", required=True, help="thu muc chua dataset_final.csv (phase1/data)")
ap.add_argument("--out", required=True, help="thu muc ghi ket qua (phase2/data)")
ap.add_argument("--root", default=os.environ.get("VFF_ROOT", ""), help="VFF_ROOT (thu muc co LLMRequest/)")
ap.add_argument("--no-format-hint", action="store_true")
ap.add_argument("--limit", type=int, default=0, help="chi chay N CVE dau (de thu)")
a = ap.parse_args()
out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("VFF_LLM_CACHE", str(out / "llm_cache_phase2.jsonl"))   # phai dat TRUOC khi import ask_GPT
sys.path.insert(0, a.root)
from LLMRequest.ask_GPT import query_chat_gpt          # ban Gemini da thay o Giai doan 0
import nltk

INSTR = ("I want you to act like an expert in vulnerability report analysis, I will give you a description. "
         "Your task is to extract the attack vector and root cause from it. Attack vector is the method of "
         "triggering the vulnerability. If you can not find the corresponding answer, just answer None\n")
HINT = ('Answer in JSON with exactly the keys "Root Cause" and "Attack Vector". Each value must be copied '
        'from the INPUT text, or be "None".\n')
NONE_SET = {"", "none", "n/a", "na", "null", "not found", "not specified", "not mentioned"}


def build_prompt(sentence, hint=True):
    return INSTR + (HINT if hint else "") + f"\nINPUT:{sentence}\nOUTPUT:\n"


def find_bracket_closure(s):
    i, j = s.find("{"), s.rfind("}")
    return s[i:j + 1] if i != -1 and j != -1 and i < j else None


def _val(v):
    if isinstance(v, list):
        v = " ; ".join(str(x) for x in v if str(x).strip().lower() not in NONE_SET)
    v = (v or "").strip() if isinstance(v, str) else str(v or "").strip()
    return None if v.lower() in NONE_SET else v


def parse_answer(text):
    """-> (av, rc, ok). av/rc la chuoi hoac None. ok=False neu khong parse duoc gi."""
    t = (text or "").strip()
    if t.startswith("OUTPUT:"):
        t = t[7:].strip()
    blk = find_bracket_closure(t)
    if blk:
        try:
            d = json.loads(blk)
            low = {k.strip().lower(): v for k, v in d.items()}
            return _val(low.get("attack vector")), _val(low.get("root cause")), True
        except Exception:
            pass
    av = rc = None
    got = False
    m = re.search(r"(?is)attack vector\s*[:\-]\s*(.+?)(?:\n\s*(?:root cause|impact)\s*[:\-]|$)", t)
    if m: av, got = _val(m.group(1)), True
    m = re.search(r"(?is)root cause\s*[:\-]\s*(.+?)(?:\n\s*(?:attack vector|impact)\s*[:\-]|$)", t)
    if m: rc, got = _val(m.group(1)), True
    return av, rc, got


def main():
    rows = [r for r in csv.DictReader(open(pathlib.Path(a.data) / "dataset_final.csv", encoding="utf-8"))
            if r["in_experiment"] == "True"]
    seen, items = set(), []
    for r in rows:
        if r["cve"] not in seen and r["description"].strip():
            seen.add(r["cve"]); items.append((r["cve"], r["description"]))
    if a.limit:
        items = items[:a.limit]
    print(f"{len(items)} CVE co mo ta | model={os.environ.get('VFF_LLM_MODEL', 'gemini-3.5-flash-lite')}")
    res = []
    for k, (cve, desc) in enumerate(items, 1):
        sents = nltk.sent_tokenize(desc)
        recs, avs, rcs = [], [], []
        for s in sents:
            raw = query_chat_gpt(build_prompt(s, not a.no_format_hint))
            av, rc, ok = parse_answer(raw)
            recs.append(dict(text=s, raw=raw, av=av, rc=rc, parse_ok=ok))
            if av: avs.append(av)
            if rc: rcs.append(rc)
        res.append(dict(cve=cve, description=desc, sentences=recs, av=avs, rc=rcs))
        if k % 10 == 0:
            print(f"  {k}/{len(items)}", flush=True)
    with open(out / "extract_direct.jsonl", "w", encoding="utf-8") as f:
        for r in res:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    ns = sum(len(r["sentences"]) for r in res)
    bad = [(r["cve"], s["text"][:60]) for r in res for s in r["sentences"] if not s["parse_ok"]]
    wc = lambda L: [len(x.split()) for r in res for x in r[L]]
    avw, rcw = wc("av"), wc("rc")
    print("\n=== TOM TAT (Direct) ===")
    print(f"CVE: {len(res)} | cau: {ns} | khong parse duoc: {len(bad)}")
    print(f"CVE co AV: {sum(1 for r in res if r['av'])}  | CVE co RC: {sum(1 for r in res if r['rc'])}")
    print(f"So tu trung binh moi muc trich: AV={sum(avw)/max(1,len(avw)):.1f} RC={sum(rcw)/max(1,len(rcw)):.1f}")
    for c, s in bad[:10]:
        print("  [khong parse] ", c, s)
    print(f"Da ghi {out/'extract_direct.jsonl'}")


if __name__ == "__main__":
    main()
