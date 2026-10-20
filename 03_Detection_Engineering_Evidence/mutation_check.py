"""
Mutation check: inject deliberate bugs into engine.py and confirm the test-suite FAILS (mutant 'killed').
A surviving mutant means a test gap. Run: python mutation_check.py
"""
import shutil, subprocess, sys, pathlib, tempfile, json

MUTANTS = [
    ("D06 threshold compare > to >=",        'if total > thr and',                       'if total >= thr and'),
    ("D02 ignore MFA flag",                  'e.get("mfa") is False',                    'True'),
    ("D03 drop self-approval check",         'self_approved = e.get("approver") in (None, e["actor"])', 'self_approved = False'),
    ("D05 compare exact IP not /24",         'net = _net24(e["ip"])',                    'net = e["ip"]'),
    ("D07 ignore allowlist",                 'e["dst_ip"] not in allow\n                    and t0',  'True\n                    and t0'),
    ("D09 skip prohibited tools",            'if tool in c["prohibited_tools"]:',        'if False:'),
    ("D11 also alert on read-only tools",    'if e["tool"] not in ro and',               'if True and'),
    ("D12 wrong gap comparison",             'if b - a >= gap:',                         'if b - a >= gap * 10:'),
    ("D13 disable rule",                     'for e in events if e["source"] == "cloud" and e["event"] in bad]', 'for e in events if False]'),
    ("D15 leak raw value in alert",          'value={masked}',                           'value={m.group(1)}'),
    ("D01 ignore failure window",            '_max_in_window(recent, win) >= c["fail_threshold"]', 'True'),
    ("D16 use > cap x10",                    'total > c["tenant_token_cap"]',            'total > c["tenant_token_cap"] * 10'),
]

src = pathlib.Path("engine.py").read_text()
killed = 0
rows = []
for name, old, new in MUTANTS:
    if old not in src:
        rows.append((name, "PATTERN NOT FOUND")); continue
    with tempfile.TemporaryDirectory() as d:
        for f in ["test_rules.py", "config.json"]:
            shutil.copy(f, d)
        shutil.copytree("data", pathlib.Path(d) / "data")
        (pathlib.Path(d) / "engine.py").write_text(src.replace(old, new, 1))
        r = subprocess.run([sys.executable, "-m", "unittest", "test_rules"], cwd=d, capture_output=True, text=True)
        status = "KILLED" if r.returncode != 0 else "SURVIVED"
        killed += status == "KILLED"
        rows.append((name, status))
for n, s in rows:
    print(f"{s:9s} {n}")
print(f"\n{killed}/{len(MUTANTS)} mutants killed")
json.dump({"mutants": [{"name": n, "status": s} for n, s in rows], "killed": killed, "total": len(MUTANTS)},
          open("results/mutation_check.json", "w"), indent=2)
