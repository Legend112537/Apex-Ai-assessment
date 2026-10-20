# Detection Engineering Exercise (Part 18) — Apex AI Arabia Cybersecurity Engineer Assessment

**What this is:** 16 detection rules for a healthcare AI platform (identity, privilege, data exfiltration, AI-agent
behaviour, control failure, secrets, PHI-in-logs, cost abuse), a synthetic log generator with 11 labelled attack
scenarios and deliberate benign near-misses, 50 unit tests, a mutation check, and an evaluation harness.

**What this is NOT:** proof of production accuracy. All data is synthetic and the same author wrote data and rules.
Results show the implementation behaves as designed. Real precision/recall must be measured on 2-4 weeks of the
customer's baseline logs before any alert is trusted or any automated response is enabled.

## Reproduce (Python 3.10+, no third-party packages)
```
python generate_logs.py          # writes data/benign.jsonl, data/attack.jsonl, data/ground_truth.json (seed 42)
python -m unittest -v test_rules # 50 tests
python mutation_check.py         # injects 12 deliberate bugs; every mutant must be killed by the tests
python run_eval.py               # writes results/*
```

## Files
| File | Purpose |
|---|---|
| engine.py | 16 rules + registry (`RULE_CATALOG`) |
| config.json | thresholds and allow-lists (starting hypotheses, to be tuned) |
| generate_logs.py | synthetic events; RFC 5737 documentation IPs; obviously fake identifiers |
| test_rules.py | positive, negative and boundary tests for every rule + 3 end-to-end tests |
| mutation_check.py | proves the tests can detect broken rules |
| run_eval.py | scenario scoring, time-to-detect, S4 exposure model, D06 threshold sensitivity |
| results/ | alerts (json/csv), evaluation.json, threshold_sensitivity.csv, s4_timeline.json, test_output.txt, mutation_check.json |

## Known limitations (stated up front)
1. Synthetic data; rules and data share an author (self-fulfilling risk).
2. Batch evaluation. A SIEM would run these as streaming or scheduled queries; alert time here is the event time that crossed the condition.
3. D05 learns a /24 baseline from the first 12 hours; a real deployment needs a rolling baseline and onboarding of new services.
4. D15 uses context-keyword regexes. National-ID checksum validation should be added once the official algorithm is confirmed.
5. Thresholds (e.g. 5,000 records / 10 min for service accounts) are conservative week-1 defaults, not tuned values.
6. The "auto-revoke in 120 s" figure in the S4 exposure model is a design target/assumption, not a measured value.
