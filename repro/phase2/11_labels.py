#!/usr/bin/env python3
"""Giai doan 2 - Buoc 2.2: lap tap NHAN VANG (gold) cho Attack Vector / Root Cause.

  python 11_labels.py split --data repro/phase1/data --out repro/phase2/data [--n-indep 20 --n-draft 40 --seed 11]
      -> chia ngau nhien (co dinh seed): 'indep' (ban tu gan nhan DOC LAP, khong xem dau ra mo hinh)
         va 'draft_pool' (se duoc mo hinh soan nhap roi ban ra soat). Ghi label_split.json + label_sheet_indep.csv
  python 11_labels.py fill --sheet <file.csv>
      -> hoi dap tung CVE: ban go AV va RC, script KIEM TRA NGAY (moi muc phai la chuoi con cua mo ta), luu sau moi dong.
  python 11_labels.py check --sheet <file.csv>
      -> kiem tra nhan: moi muc phai la CHUOI CON cua mo ta (khong dien giai lai), bao loi go.

Quy uoc dien (xem huong dan): nhieu muc ngan cach bang ' || '. Khong co -> de trong hoac ghi None.
"""
import argparse, csv, json, pathlib, random, re, textwrap

ap = argparse.ArgumentParser()
ap.add_argument("mode", choices=["split", "fill", "check"])
ap.add_argument("--data")
ap.add_argument("--out")
ap.add_argument("--sheet")
ap.add_argument("--n-indep", type=int, default=20)
ap.add_argument("--n-draft", type=int, default=40)
ap.add_argument("--seed", type=int, default=11)
a = ap.parse_args()

norm = lambda s: re.sub(r"\s+", " ", s).strip().lower()


def bad_parts(value, description):
    d = norm(description)
    return [p.strip() for p in value.split("||") if norm(p) and norm(p) not in d]

if a.mode == "split":
    rows = [r for r in csv.DictReader(open(pathlib.Path(a.data) / "dataset_final.csv", encoding="utf-8"))
            if r["in_experiment"] == "True"]
    desc = {}
    for r in rows:
        if r["description"].strip():
            desc.setdefault(r["cve"], " ".join(r["description"].split()))
    cves = sorted(desc)
    rnd = random.Random(a.seed)
    rnd.shuffle(cves)
    indep = sorted(cves[:a.n_indep])
    draft = sorted(cves[a.n_indep:a.n_indep + a.n_draft])
    rest = sorted(cves[a.n_indep + a.n_draft:])
    out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
    json.dump(dict(seed=a.seed, indep=indep, draft_pool=draft, unlabeled=rest), open(out / "label_split.json", "w"), indent=1)
    with open(out / "label_sheet_indep.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cve", "description", "av_gold", "rc_gold", "note"])
        for c in indep:
            w.writerow([c, desc[c], "", "", ""])
    print(f"CVE co mo ta: {len(desc)} | indep={len(indep)} | draft_pool={len(draft)} | khong gan nhan={len(rest)}")
    print(f"Da ghi {out/'label_split.json'} va {out/'label_sheet_indep.csv'}")

elif a.mode == "fill":
    with open(a.sheet, newline="", encoding="utf-8") as f:
        rd = csv.DictReader(f); cols = rd.fieldnames; rows = list(rd)
    def save():
        with open(a.sheet, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(rows)
    def ask(label, desc):
        while True:
            v = input(f"   {label} (Enter = None | s = bo qua | q = thoat): ").strip()
            if v.lower() in ("s", "q"):
                return v.lower()
            if v == "" or v.lower() == "none":
                return "None"
            bad = bad_parts(v, desc)
            if not bad:
                return v
            print("   KHONG phai chuoi con cua mo ta: " + " | ".join(repr(b) for b in bad) + "  -> go lai")
    todo = [i for i, r in enumerate(rows) if not (r["av_gold"].strip() or r["rc_gold"].strip())]
    print(f"{len(todo)}/{len(rows)} dong chua gan nhan.  Nhieu muc cach nhau bang ' || '.\n")
    quit_all = False
    for k, i in enumerate(todo, 1):
        r = rows[i]
        print("=" * 78)
        print(f"[{k}/{len(todo)}] {r['cve']}")
        print(textwrap.fill(r["description"], 100, initial_indent="   ", subsequent_indent="   "))
        av = ask("ATTACK VECTOR", r["description"])
        if av == "q": break
        if av == "s": continue
        rc = ask("ROOT CAUSE   ", r["description"])
        if rc == "q": break
        if rc == "s": continue
        r["av_gold"], r["rc_gold"] = av, rc
        r["note"] = input("   ghi chu (Enter de bo qua): ").strip()
        save()
    save()
    done = sum(1 for r in rows if r["av_gold"].strip() or r["rc_gold"].strip())
    print(f"\nDa luu {a.sheet}. Da gan nhan {done}/{len(rows)}.")

else:
    rows = list(csv.DictReader(open(a.sheet, encoding="utf-8")))
    bad, n_av, n_rc, empty = [], 0, 0, 0
    for r in rows:
        d = norm(r["description"])
        got = False
        for col, tag in (("av_gold", "AV"), ("rc_gold", "RC")):
            v = (r[col] or "").strip()
            if v.lower() in ("", "none"):
                continue
            got = True
            n_av += tag == "AV"; n_rc += tag == "RC"
            for part in v.split("||"):
                p = norm(part)
                if p and p not in d:
                    bad.append((r["cve"], tag, part.strip()))
        if not got:
            empty += 1
    print(f"Dong: {len(rows)} | co AV: {n_av} | co RC: {n_rc} | khong co AV lan RC: {empty}")
    if bad:
        print(f"\n{len(bad)} muc KHONG phai chuoi con cua mo ta (kiem tra loi go / dien giai lai):")
        for c, t, p in bad:
            print(f"  {c} [{t}] {p!r}")
    else:
        print("OK: moi nhan deu la chuoi con cua mo ta.")
