"""
Evaluation harness. Produces everything quoted in Part 18 of the report.
Run:  python generate_logs.py && python run_eval.py
All results are on SYNTHETIC data authored by the same person who wrote the rules, so they demonstrate that the
implementation behaves as designed. They are NOT an estimate of production precision/recall.
"""
import copy
import csv
import json
from datetime import datetime, timedelta

import engine

cfg = engine.load_config("config.json")
benign = engine.load_events("data/benign.jsonl")
attack = engine.load_events("data/attack.jsonl")
truth = json.load(open("data/ground_truth.json"))

P = engine.parse_ts

# ---------------------------------------------------------------- run both days
alerts_benign = engine.run_all(benign, cfg)
alerts_attack = engine.run_all(attack, cfg)

# ---------------------------------------------------------------- scenario scoring
scenario_rows, matched_ids = [], set()
for s in truth:
    start = P(s["start"])
    end = start + timedelta(minutes=s["window_min"])
    found, first_ts, last_ts = {}, None, None
    for i, a in enumerate(alerts_attack):
        ts = P(a["ts"])
        if a["rule"] in s["expected"] and start - timedelta(seconds=1) <= ts <= end:
            found.setdefault(a["rule"], ts)
            matched_ids.add(i)
    detected = all(r in found for r in s["expected"])
    if found:
        first_ts, last_ts = min(found.values()), max(found.values())
    scenario_rows.append({
        "id": s["id"], "name": s["name"], "expected": ",".join(s["expected"]),
        "fired": ",".join(sorted(found)), "detected": detected,
        "time_to_first_alert_s": None if first_ts is None else round((first_ts - start).total_seconds(), 1),
        "time_to_full_coverage_s": None if last_ts is None else round((last_ts - start).total_seconds(), 1),
    })

unexpected = [a for i, a in enumerate(alerts_attack) if i not in matched_ids]

# ---------------------------------------------------------------- S4 exposure analysis
def s4_attack_calls():
    return [e for e in attack if e["source"] == "api" and e["actor"] == "svc-analytics" and e.get("records") == 500]

calls = s4_attack_calls()
d06 = next(a for a in alerts_attack if a["rule"] == "D06")
t_d06 = P(d06["ts"])
total_records = sum(c["records"] for c in calls)
at_alert = sum(c["records"] for c in calls if c["_ts"] <= t_d06)
DELAY_S = 120  # design target for automated credential revoke after alert (NOT measured; assumption)
at_contained = sum(c["records"] for c in calls if c["_ts"] <= t_d06 + timedelta(seconds=DELAY_S))
s4_start = calls[0]["_ts"]
egress = next(e for e in attack if e["source"] == "egress" and e["dst_ip"] == "203.0.113.45")

# per-minute timeline for the chart
timeline = []
t = s4_start.replace(second=0) - timedelta(minutes=3)
cum = 0
while t <= egress["_ts"] + timedelta(minutes=3):
    n = sum(c["records"] for c in calls if t <= c["_ts"] < t + timedelta(minutes=1))
    cum += n
    timeline.append({"t": t.isoformat(), "records_per_min": n, "cumulative": cum})
    t += timedelta(minutes=1)

s4 = {
    "total_records": total_records,
    "start": s4_start.isoformat(),
    "d06_alert": d06["ts"],
    "seconds_start_to_d06": round((t_d06 - s4_start).total_seconds(), 1),
    "records_at_d06_alert": at_alert,
    "pct_at_alert": round(100 * at_alert / total_records, 1),
    "assumed_auto_revoke_delay_s": DELAY_S,
    "records_if_auto_revoke": at_contained,
    "pct_if_auto_revoke": round(100 * at_contained / total_records, 1),
    "egress_ts": egress["_ts"].isoformat(),
    "egress_bytes": egress["bytes"],
    "alerts": {a["rule"]: a["ts"] for a in alerts_attack if a["rule"] in ("D06", "D07", "D08") and a["actor"] == "svc-analytics"},
}

# ---------------------------------------------------------------- D06 threshold sensitivity
sens = []
for thr in [500, 1000, 2000, 3000, 5000, 8000, 10000, 15000]:
    c2 = copy.deepcopy(cfg)
    c2["mass_read"]["service_threshold"] = thr
    c2["mass_read"]["per_actor_override"] = {}
    fp = [a for a in engine.d06_mass_record_access(benign, c2)]
    fp_actors = sorted({a["actor"] for a in fp})
    att = [a for a in engine.d06_mass_record_access(attack, c2) if a["actor"] == "svc-analytics"]
    if att:
        ta = P(att[0]["ts"])
        exposed = sum(c["records"] for c in calls if c["_ts"] <= ta)
    else:
        exposed = total_records  # never detected
    sens.append({"service_threshold": thr, "benign_false_alerts": len(fp), "benign_fp_actors": ";".join(fp_actors),
                 "s4_records_exposed_at_alert": exposed, "s4_pct_exposed": round(100 * exposed / total_records, 1)})

# ---------------------------------------------------------------- outputs
json.dump(alerts_attack, open("results/alerts_attack_day.json", "w"), indent=2)
with open("results/alerts_attack_day.csv", "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["time_utc", "rule", "severity", "actor", "mapping", "detail"])
    for a in alerts_attack:
        w.writerow([a["ts"], a["rule"], a["severity"], a["actor"], a["mapping"], a["detail"]])
with open("results/threshold_sensitivity.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(sens[0].keys()))
    w.writeheader()
    w.writerows(sens)
json.dump(timeline, open("results/s4_timeline.json", "w"), indent=2)

summary = {
    "dataset": {"benign_events": len(benign), "attack_day_events": len(attack), "scenarios": len(truth),
                "rules": len(engine.RULE_CATALOG), "seed": 42, "data_is_synthetic": True},
    "benign_day_alerts": len(alerts_benign),
    "attack_day_alerts": len(alerts_attack),
    "scenarios_detected": sum(r["detected"] for r in scenario_rows),
    "scenarios_total": len(scenario_rows),
    "unexpected_alerts_on_attack_day": len(unexpected),
    "scenario_results": scenario_rows,
    "s4_exposure": s4,
    "rules_fired_on_attack_day": sorted({a["rule"] for a in alerts_attack}),
}
json.dump(summary, open("results/evaluation.json", "w"), indent=2)

# ---------------------------------------------------------------- console
print(f"benign day: {len(benign)} events -> {len(alerts_benign)} alerts (false positives)")
print(f"attack day: {len(attack)} events -> {len(alerts_attack)} alerts; scenarios detected "
      f"{summary['scenarios_detected']}/{summary['scenarios_total']}; unexpected alerts {len(unexpected)}")
for r in scenario_rows:
    print(f"  {r['id']:3s} detected={r['detected']!s:5s} first={r['time_to_first_alert_s']}s full={r['time_to_full_coverage_s']}s  {r['name']}")
print("S4:", json.dumps({k: v for k, v in s4.items() if k != 'alerts'}, indent=1))
print("D06 sensitivity:")
for r in sens:
    print("  ", r)
