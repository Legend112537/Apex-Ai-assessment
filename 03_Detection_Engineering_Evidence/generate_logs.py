"""
Synthetic log generator for the Apex detection-engineering exercise.

IMPORTANT: every record is SYNTHETIC. Identities, IDs and IPs are invented. Public IPs use
RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Patient-like
identifiers are obviously fake. Nothing here is customer data.

Usage: python generate_logs.py            -> data/benign.jsonl, data/attack.jsonl, data/ground_truth.json
Seeded for reproducibility (seed=42).
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone

SEED = 42
DAY = datetime(2026, 9, 18, 0, 0, 0, tzinfo=timezone.utc)


def T(h, m=0, s=0):
    return DAY + timedelta(hours=h, minutes=m, seconds=s)


def ev(ts, source, event, **kw):
    d = {"ts": ts.isoformat().replace("+00:00", "Z"), "source": source, "event": event}
    d.update(kw)
    return d


# ---------------------------------------------------------------------------
# baseline (normal) activity, including deliberate benign near-misses
# ---------------------------------------------------------------------------

def build_benign(rng: random.Random) -> list[dict]:
    out: list[dict] = []
    clinicians = [f"dr.user{i:02d}" for i in range(1, 31)]
    admins = ["admin.rania", "admin.omar", "admin.sara", "admin.khalid"]
    customers = [f"cust-{n:04d}" for n in range(1, 400)]

    # heartbeats from every log source every minute (used by silence rule)
    for src in ["api-gateway", "auth", "cloud-audit", "waf", "app"]:
        for minute in range(24 * 60):
            out.append(ev(DAY + timedelta(minutes=minute), "log_pipeline", "heartbeat", log_source=src))

    # clinician logins (MFA on), 0-2 typos first (benign failures)
    for u in clinicians:
        for _ in range(rng.randint(1, 3)):
            t = T(rng.randint(6, 16), rng.randint(0, 59), rng.randint(0, 59))
            ip = rng.choice(["192.0.2.%d" % rng.randint(30, 60), "10.20.1.%d" % rng.randint(2, 200)])
            for k in range(rng.choice([0, 0, 1, 2])):
                out.append(ev(t - timedelta(seconds=20 * (k + 1)), "auth", "login", actor=u, actor_type="human",
                              role="user", outcome="failure", ip=ip, mfa=None))
            out.append(ev(t, "auth", "login", actor=u, actor_type="human", role="user", outcome="success",
                          ip=ip, mfa=True))
        # single-record reads during working hours
        for _ in range(rng.randint(20, 120)):
            out.append(ev(T(rng.randint(6, 17), rng.randint(0, 59), rng.randint(0, 59)), "api", "record_read",
                          actor=u, actor_type="human", records=1, endpoint="/documents/{id}",
                          ip="192.0.2.%d" % rng.randint(30, 60)))

    # BENIGN NEAR-MISS: a busy clinician reads 45 records in 10 minutes (below human threshold)
    for k in range(45):
        out.append(ev(T(10, 0) + timedelta(seconds=13 * k), "api", "record_read", actor="dr.user07",
                      actor_type="human", records=1, endpoint="/documents/{id}", ip="192.0.2.41"))

    # BENIGN NEAR-MISS: developer fumbles password 3 times then succeeds with MFA
    for k in range(3):
        out.append(ev(T(9, 30) + timedelta(seconds=15 * k), "auth", "login", actor="dev.ali", actor_type="human",
                      role="user", outcome="failure", ip="10.20.9.14", mfa=None))
    out.append(ev(T(9, 31), "auth", "login", actor="dev.ali", actor_type="human", role="user",
                  outcome="success", ip="10.20.9.14", mfa=True))

    # admin logins with MFA
    for a in admins:
        out.append(ev(T(rng.randint(7, 15), rng.randint(0, 59)), "auth", "login", actor=a, actor_type="human",
                      role="Admin", outcome="success", ip="10.30.0.%d" % rng.randint(2, 20), mfa=True))

    # BENIGN NEAR-MISS: approved privileged grant with change ticket and different approver
    out.append(ev(T(8, 45), "cloud", "role_grant", actor="admin.rania", target="dr.user03", role="Admin",
                  change_ticket="CHG-1042", approver="admin.omar"))
    # BENIGN NEAR-MISS: onboarding of 3 users in 10 minutes
    for k in range(3):
        out.append(ev(T(9, 0) + timedelta(minutes=3 * k), "cloud", "user_create", actor="admin.sara",
                      target=f"newhire{k}"))
    # benign WAF rule tuning (not a control being disabled)
    out.append(ev(T(11, 5), "cloud", "waf_rule_updated", actor="admin.omar", resource="waf-prod"))

    # service accounts
    # svc-report-batch: heavy but legitimate batch jobs (BENIGN NEAR-MISS for mass-read)
    for start in [T(2, 0), T(11, 0)]:
        for k in range(15):
            out.append(ev(start + timedelta(minutes=2 * k), "api", "record_read", actor="svc-report-batch",
                          actor_type="service", records=rng.randint(350, 450), endpoint="/reports/batch",
                          ip="10.0.4.%d" % rng.randint(10, 20)))
    # svc-analytics: steady small reads and allowlisted egress
    for k in range(24 * 12):
        out.append(ev(DAY + timedelta(minutes=5 * k), "api", "record_read", actor="svc-analytics",
                      actor_type="service", records=rng.randint(30, 70), endpoint="/analytics/read",
                      ip="10.0.5.%d" % rng.randint(10, 20)))
    for k in range(48):
        out.append(ev(DAY + timedelta(minutes=30 * k + 7), "egress", "connection", actor="svc-analytics",
                      dst_ip="192.0.2.25", dst_port=443, bytes=rng.randint(1_000_000, 3_000_000)))
    # svc-integration: steady calls; BENIGN NEAR-MISS pod restart -> new IP in the SAME /24 at 14:00
    for k in range(24 * 6):
        t = DAY + timedelta(minutes=10 * k)
        ip = "10.0.6.44" if t >= T(14, 0) else "10.0.6.%d" % rng.randint(10, 20)
        out.append(ev(t, "auth", "token_issued", actor="svc-integration", actor_type="service", ip=ip))
        out.append(ev(t + timedelta(seconds=5), "api", "record_read", actor="svc-integration", actor_type="service",
                      records=rng.randint(1, 5), endpoint="/integration/fetch", ip=ip))
    # LLM egress via allowlisted proxy
    for k in range(24):
        out.append(ev(T(k, 3), "egress", "connection", actor="llm-gateway", dst_ip="198.51.100.10", dst_port=443,
                      bytes=rng.randint(200_000, 900_000)))

    # AI agents: normal usage
    agents = ["agent-support-01", "agent-billing-01", "agent-intake-01"]
    sess = 0
    for a in agents:
        for _ in range(60):
            sess += 1
            base = T(rng.randint(6, 17), rng.randint(0, 59), rng.randint(0, 59))
            for k in range(rng.randint(1, 4)):
                tool = rng.choice(["search_customer", "search_customer", "read_invoice"])
                out.append(ev(base + timedelta(seconds=20 * k), "agent", "tool_call", actor=a, actor_type="agent",
                              tool=tool, session=f"sess-{sess}", customer=rng.choice(customers),
                              approval_token=False, tainted=False))
    # legitimate approved refund
    out.append(ev(T(12, 15), "agent", "tool_call", actor="agent-billing-01", actor_type="agent", tool="issue_refund",
                  session="sess-refund-ok", customer="cust-0042", approval_token=True, tainted=False))
    # BENIGN NEAR-MISS: agent does 12 calls / 8 customers within 5 minutes
    for k in range(12):
        out.append(ev(T(13, 0) + timedelta(seconds=20 * k), "agent", "tool_call", actor="agent-intake-01",
                      actor_type="agent", tool="search_customer", session="sess-busy", customer=f"cust-{100 + k % 8:04d}",
                      approval_token=False, tainted=False))
    # BENIGN NEAR-MISS: injection indicator raised, agent stayed read-only (no side effect)
    out.append(ev(T(14, 30), "llm", "retrieval", actor="agent-support-01", session="sess-inj-benign",
                  injection_flag=True))
    out.append(ev(T(14, 30, 20), "agent", "tool_call", actor="agent-support-01", actor_type="agent",
                  tool="search_customer", session="sess-inj-benign", customer="cust-0300", approval_token=False,
                  tainted=True))

    # LLM token usage: two tenants, ~40k tokens/hour each
    for tenant in ["tenant-a", "tenant-b"]:
        for k in range(24 * 20):
            out.append(ev(DAY + timedelta(minutes=3 * k), "llm", "completion", actor="llm-gateway",
                          tenant=tenant, tokens=rng.randint(1500, 2500)))

    # git pushes without secrets
    for k in range(40):
        out.append(ev(T(rng.randint(8, 18), rng.randint(0, 59)), "git", "push", actor=rng.choice(["dev.ali", "dev.noor", "dev.zaid"]),
                      repo="apex/platform", secret_findings=0))

    # application log lines; BENIGN NEAR-MISS: 10-digit numbers without PHI context
    for k in range(300):
        out.append(ev(T(rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59)), "app_log", "log_line",
                      actor="app", message=f"request_id=req-{rng.randint(10**6, 10**7)} status=200 latency_ms={rng.randint(20, 400)}"))
    out.append(ev(T(10, 22), "app_log", "log_line", actor="app",
                  message="order_no 1234567890 processed; support phone 0501234567"))
    return out


# ---------------------------------------------------------------------------
# labelled attack scenarios
# ---------------------------------------------------------------------------

def build_attacks(rng: random.Random):
    out: list[dict] = []
    truth: list[dict] = []
    ATT = "198.51.100.23"

    # S1 credential attack on an admin (no MFA on legacy path)
    t0 = T(2, 10)
    for k in range(25):
        out.append(ev(t0 + timedelta(seconds=7 * k), "auth", "login", actor="admin.rania", actor_type="human",
                      role="Admin", outcome="failure", ip=ATT, mfa=None))
    out.append(ev(t0 + timedelta(seconds=240), "auth", "login", actor="admin.rania", actor_type="human", role="Admin",
                  outcome="success", ip=ATT, mfa=False))
    truth.append({"id": "S1", "name": "Admin credential attack, success without MFA", "start": t0.isoformat(),
                  "expected": ["D01", "D02"], "window_min": 15})

    # S2 attacker privilege abuse
    t1 = T(2, 16)
    out.append(ev(t1, "cloud", "role_grant", actor="admin.rania", target="svc-backup2", role="Admin",
                  change_ticket=None, approver=None))
    for k in range(6):
        out.append(ev(t1 + timedelta(minutes=1 + k * 0.7), "cloud", "user_create", actor="admin.rania",
                      target=f"tmp-user{k}"))
    truth.append({"id": "S2", "name": "Privilege escalation and backdoor accounts", "start": t1.isoformat(),
                  "expected": ["D03", "D04"], "window_min": 15})

    # S3 stolen service credential used from a new network (after the 12h baseline)
    t2 = T(15, 5)
    out.append(ev(t2, "auth", "token_issued", actor="svc-integration", actor_type="service", ip="198.51.100.77"))
    out.append(ev(t2 + timedelta(seconds=10), "api", "record_read", actor="svc-integration", actor_type="service",
                  records=3, endpoint="/integration/fetch", ip="198.51.100.77"))
    truth.append({"id": "S3", "name": "Service credential used from unseen network", "start": t2.isoformat(),
                  "expected": ["D05"], "window_min": 5})

    # S4 the brief's incident: 25,000 records in 12 minutes then unknown external IP
    t3 = T(15, 20)
    for k in range(50):  # 50 calls x 500 records = 25,000 over ~12 minutes
        out.append(ev(t3 + timedelta(seconds=14.4 * k), "api", "record_read", actor="svc-analytics",
                      actor_type="service", records=500, endpoint="/analytics/read", ip="10.0.5.15"))
    out.append(ev(T(15, 36), "egress", "connection", actor="svc-analytics", dst_ip="203.0.113.45", dst_port=443,
                  bytes=412_000_000))
    truth.append({"id": "S4", "name": "Service account reads 25,000 records in 12 min, then external egress",
                  "start": t3.isoformat(), "expected": ["D06", "D07", "D08"], "window_min": 40})

    # S5 agent uses unapproved refund and a prohibited tool
    t4 = T(10, 40)
    out.append(ev(t4, "agent", "tool_call", actor="agent-support-01", actor_type="agent", tool="issue_refund",
                  session="sess-x1", customer="cust-0777", approval_token=False, tainted=True))
    out.append(ev(t4 + timedelta(seconds=30), "agent", "tool_call", actor="agent-support-01", actor_type="agent",
                  tool="create_user", session="sess-x1", customer=None, approval_token=False, tainted=True))
    truth.append({"id": "S5", "name": "Agent executes unapproved/prohibited tools", "start": t4.isoformat(),
                  "expected": ["D09"], "window_min": 5})

    # S6 agent customer enumeration
    t5 = T(9, 15)
    for k in range(62):
        out.append(ev(t5 + timedelta(seconds=4 * k), "agent", "tool_call", actor="agent-intake-01",
                      actor_type="agent", tool="search_customer", session="sess-enum", customer=f"cust-{200 + k:04d}",
                      approval_token=False, tainted=True))
    truth.append({"id": "S6", "name": "Agent enumerates customers", "start": t5.isoformat(),
                  "expected": ["D10"], "window_min": 10})

    # S7 indirect prompt injection leads to an (auto-approved) side-effect tool call
    t6 = T(13, 30)
    out.append(ev(t6, "llm", "retrieval", actor="agent-billing-01", session="sess-inj-1", injection_flag=True))
    out.append(ev(t6 + timedelta(seconds=40), "agent", "tool_call", actor="agent-billing-01", actor_type="agent",
                  tool="update_customer", session="sess-inj-1", customer="cust-0555", approval_token=True, tainted=True))
    truth.append({"id": "S7", "name": "Indirect injection then side-effect call", "start": t6.isoformat(),
                  "expected": ["D11"], "window_min": 5})

    # S8 defences impaired: WAF to detect-only, then API-gateway logs go silent for 26 minutes
    t7 = T(3, 40)
    out.append(ev(T(3, 41), "cloud", "waf_mode_detect_only", actor="admin.khalid", resource="waf-prod"))
    truth.append({"id": "S8", "name": "WAF weakened and gateway logging silent", "start": t7.isoformat(),
                  "expected": ["D12", "D13"], "window_min": 30, "remove_heartbeats": ("api-gateway", t7, T(4, 6))})

    # S9 secret pushed to Git
    t8 = T(16, 10)
    out.append(ev(t8, "git", "push", actor="dev.noor", repo="apex/platform", secret_findings=1))
    truth.append({"id": "S9", "name": "Secret committed", "start": t8.isoformat(), "expected": ["D14"], "window_min": 5})

    # S10 PHI in prompt logs (fake identifiers)
    t9 = T(17, 5)
    out.append(ev(t9, "prompt_log", "prompt_logged", actor="assistant-svc",
                  message="user asked: summarise visit for national_id: 1000000001 mrn 00123456"))
    truth.append({"id": "S10", "name": "PHI written to prompt logs", "start": t9.isoformat(),
                  "expected": ["D15"], "window_min": 5})

    # S11 denial-of-wallet on one tenant
    t10 = T(18, 0)
    for k in range(30):
        out.append(ev(t10 + timedelta(minutes=k), "llm", "completion", actor="llm-gateway", tenant="tenant-b",
                      tokens=20_000))
    truth.append({"id": "S11", "name": "Token spike (denial-of-wallet)", "start": t10.isoformat(),
                  "expected": ["D16"], "window_min": 45})
    return out, truth


def main():
    rng = random.Random(SEED)
    benign = build_benign(rng)
    attacks, truth = build_attacks(rng)

    # apply heartbeat removal for S8 in the attack dataset
    combined = []
    removals = [t["remove_heartbeats"] for t in truth if "remove_heartbeats" in t]
    for e in benign:
        drop = False
        for src, a, b in removals:
            if e["source"] == "log_pipeline" and e.get("log_source") == src:
                ts = datetime.fromisoformat(e["ts"].replace("Z", "+00:00"))
                if a <= ts < b:
                    drop = True
        if not drop:
            combined.append(e)
    combined += attacks

    for t in truth:
        t.pop("remove_heartbeats", None)

    with open("data/benign.jsonl", "w") as fh:
        for e in sorted(benign, key=lambda x: x["ts"]):
            fh.write(json.dumps(e) + "\n")
    with open("data/attack.jsonl", "w") as fh:
        for e in sorted(combined, key=lambda x: x["ts"]):
            fh.write(json.dumps(e) + "\n")
    with open("data/ground_truth.json", "w") as fh:
        json.dump(truth, fh, indent=2)
    print(f"benign events: {len(benign)}  attack-day events: {len(combined)}  scenarios: {len(truth)}")


if __name__ == "__main__":
    main()
