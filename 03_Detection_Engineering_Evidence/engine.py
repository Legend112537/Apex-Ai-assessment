"""
Apex AI Arabia - Detection Engineering exercise (Part 18)
16 detection rules over normalized JSON-lines events.

Design notes
- Pure Python, no dependencies, so the logic is reviewable and portable to a SIEM
  (KQL / SPL / Elastic EQL) once thresholds are validated on real baseline data.
- Every rule returns alerts that carry rule id, severity, MITRE ATT&CK technique,
  timestamp of the event that CROSSED the condition (used to measure time-to-detect),
  and a short detail string. Alerts never contain raw PHI values.
- Thresholds live in config.json. They are starting hypotheses, not tuned values.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------

def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def load_events(path: str) -> list[dict]:
    events = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            e["_ts"] = parse_ts(e["ts"])
            events.append(e)
    events.sort(key=lambda e: e["_ts"])
    return events


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _alert(rule, name, severity, ts, actor, detail, mapping, **extra):
    a = {
        "rule": rule,
        "name": name,
        "severity": severity,
        "ts": ts.isoformat(),
        "actor": actor,
        "detail": detail,
        "mapping": mapping,
    }
    a.update(extra)
    return a


def _net24(ip: str) -> str:
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return ip


def _max_in_window(times: list[datetime], window: timedelta) -> int:
    """Largest number of timestamps that fit inside any window of given length."""
    best, j = 0, 0
    for i, t in enumerate(times):
        while t - times[j] > window:
            j += 1
        best = max(best, i - j + 1)
    return best


# ----------------------------------------------------------------------------
# D01 - D05 : identity and privilege
# ----------------------------------------------------------------------------

def d01_bruteforce_then_success(events, cfg):
    c = cfg["bruteforce"]
    win = timedelta(minutes=c["window_min"])
    look_back = timedelta(minutes=c["window_min"] + c["success_within_min"])
    by_ip = defaultdict(list)
    for e in events:
        if e["source"] == "auth" and e["event"] == "login":
            by_ip[e["ip"]].append(e)
    out = []
    for ip, evs in by_ip.items():
        fails: list[datetime] = []
        for e in evs:
            if e["outcome"] == "failure":
                fails.append(e["_ts"])
                continue
            recent = [t for t in fails if e["_ts"] - t <= look_back]
            if len(recent) >= c["fail_threshold"] and _max_in_window(recent, win) >= c["fail_threshold"]:
                out.append(_alert(
                    "D01", "Brute force followed by successful login", "High", e["_ts"], e["actor"],
                    f"{len(recent)} failed logins from {ip} then success", "T1110",
                    ip=ip))
                fails = []  # one alert per episode
    return out


def d02_privileged_login_no_mfa(events, cfg):
    priv = set(cfg["privileged_roles"])
    out = []
    for e in events:
        if (e["source"] == "auth" and e["event"] == "login" and e["outcome"] == "success"
                and e.get("role") in priv and e.get("mfa") is False):
            out.append(_alert("D02", "Privileged login without MFA", "High", e["_ts"], e["actor"],
                              f"role={e['role']} ip={e.get('ip')} mfa=false", "T1078", ip=e.get("ip")))
    return out


def d03_priv_grant_outside_change(events, cfg):
    priv = set(cfg["privileged_roles"])
    out = []
    for e in events:
        if e["source"] == "cloud" and e["event"] == "role_grant" and e.get("role") in priv:
            no_ticket = not e.get("change_ticket")
            self_approved = e.get("approver") in (None, e["actor"])
            if no_ticket or self_approved:
                why = "no change ticket" if no_ticket else "self-approved"
                out.append(_alert("D03", "Privileged role granted outside approved change", "High",
                                  e["_ts"], e["actor"],
                                  f"{e['role']} -> {e.get('target')} ({why})", "T1098"))
    return out


def d04_burst_account_creation(events, cfg):
    c = cfg["burst_user_create"]
    win = timedelta(minutes=c["window_min"])
    by_actor = defaultdict(list)
    for e in events:
        if e["source"] == "cloud" and e["event"] == "user_create":
            by_actor[e["actor"]].append(e["_ts"])
    out = []
    for actor, times in by_actor.items():
        dq: deque = deque()
        last_alert = None
        for t in times:
            dq.append(t)
            while t - dq[0] > win:
                dq.popleft()
            if len(dq) >= c["count"] and (last_alert is None or t - last_alert > win):
                out.append(_alert("D04", "Burst account creation", "High", t, actor,
                                  f"{len(dq)} accounts created within {c['window_min']} min", "T1136"))
                last_alert = t
    return out


def d05_service_account_new_network(events, cfg):
    base_end = events[0]["_ts"] + timedelta(hours=cfg["service_ip_baseline_hours"])
    baseline = defaultdict(set)
    for e in events:
        if e.get("actor_type") == "service" and e.get("ip") and e["_ts"] < base_end:
            baseline[e["actor"]].add(_net24(e["ip"]))
    out, seen = [], set()
    for e in events:
        if e.get("actor_type") != "service" or not e.get("ip") or e["_ts"] < base_end:
            continue
        if e["actor"] not in baseline:
            continue  # brand-new service: handled by asset onboarding, not this rule
        net = _net24(e["ip"])
        key = (e["actor"], net)
        if net not in baseline[e["actor"]] and key not in seen:
            seen.add(key)
            out.append(_alert("D05", "Service account used from previously unseen network", "High",
                              e["_ts"], e["actor"], f"source {e['ip']} not in baseline networks", "T1078.004",
                              ip=e["ip"]))
    return out


# ----------------------------------------------------------------------------
# D06 - D08 : data access and exfiltration
# ----------------------------------------------------------------------------

def d06_mass_record_access(events, cfg):
    c = cfg["mass_read"]
    win = timedelta(minutes=c["window_min"])
    cool = timedelta(minutes=c["cooldown_min"])
    by_actor = defaultdict(list)
    for e in events:
        if e["source"] == "api" and e["event"] == "record_read":
            by_actor[e["actor"]].append(e)
    out = []
    for actor, evs in by_actor.items():
        atype = evs[0].get("actor_type", "human")
        thr = c["per_actor_override"].get(actor, c["service_threshold"] if atype != "human" else c["human_threshold"])
        dq: deque = deque()
        total = 0
        last_alert = None
        for e in evs:
            dq.append((e["_ts"], e.get("records", 1)))
            total += e.get("records", 1)
            while e["_ts"] - dq[0][0] > win:
                total -= dq.popleft()[1]
            if total > thr and (last_alert is None or e["_ts"] - last_alert > cool):
                out.append(_alert("D06", "Mass record access", "High", e["_ts"], actor,
                                  f"{total} records in {c['window_min']} min (threshold {thr})", "T1213",
                                  records_in_window=total, threshold=thr))
                last_alert = e["_ts"]
    return out


def d07_bulk_read_then_egress(events, cfg, d06_alerts):
    allow = set(cfg["egress_allowlist"])
    horizon = timedelta(minutes=cfg["bulk_then_egress_min"])
    out = []
    for a in d06_alerts:
        t0 = datetime.fromisoformat(a["ts"])
        for e in events:
            if (e["source"] == "egress" and e["actor"] == a["actor"] and e["dst_ip"] not in allow
                    and t0 <= e["_ts"] <= t0 + horizon):
                out.append(_alert("D07", "Bulk read followed by egress to unapproved destination", "Critical",
                                  e["_ts"], a["actor"],
                                  f"mass read then {e.get('bytes', 0)} bytes to {e['dst_ip']}", "T1041",
                                  dst_ip=e["dst_ip"]))
                break
    return out


def d08_egress_unapproved(events, cfg):
    allow = set(cfg["egress_allowlist"])
    out, last = [], {}
    for e in events:
        if e["source"] != "egress" or e["dst_ip"] in allow:
            continue
        key = (e["actor"], e["dst_ip"])
        if key in last and e["_ts"] - last[key] < timedelta(minutes=60):
            continue
        last[key] = e["_ts"]
        sev = "High" if e.get("bytes", 0) >= cfg["egress_high_bytes"] else "Medium"
        out.append(_alert("D08", "Egress to unapproved destination", sev, e["_ts"], e["actor"],
                          f"dst {e['dst_ip']}:{e.get('dst_port')} bytes={e.get('bytes', 0)}", "T1048"))
    return out


# ----------------------------------------------------------------------------
# D09 - D11 : AI agent behaviour
# ----------------------------------------------------------------------------

def d09_agent_tool_policy_violation(events, cfg):
    c = cfg["agent"]
    out = []
    for e in events:
        if e["source"] != "agent" or e["event"] != "tool_call":
            continue
        tool = e["tool"]
        if tool in c["prohibited_tools"]:
            out.append(_alert("D09", "Agent called prohibited tool", "Critical", e["_ts"], e["actor"],
                              f"tool={tool} session={e.get('session')}", "OWASP-LLM06"))
        elif tool in c["approval_required_tools"] and not e.get("approval_token"):
            out.append(_alert("D09", "Agent called approval-required tool without approval", "High",
                              e["_ts"], e["actor"], f"tool={tool} session={e.get('session')}", "OWASP-LLM06"))
    return out


def d10_agent_volume_enumeration(events, cfg):
    c = cfg["agent"]
    win = timedelta(minutes=c["volume_window_min"])
    cool = timedelta(minutes=c["cooldown_min"])
    by_agent = defaultdict(list)
    for e in events:
        if e["source"] == "agent" and e["event"] == "tool_call":
            by_agent[e["actor"]].append(e)
    out = []
    for agent, evs in by_agent.items():
        dq: deque = deque()
        last_alert = None
        for e in evs:
            dq.append(e)
            while e["_ts"] - dq[0]["_ts"] > win:
                dq.popleft()
            calls = len(dq)
            distinct = len({x.get("customer") for x in dq if x["tool"] == "search_customer" and x.get("customer")})
            if (calls > c["volume_threshold"] or distinct > c["distinct_customer_threshold"]) and (
                    last_alert is None or e["_ts"] - last_alert > cool):
                out.append(_alert("D10", "Agent anomalous volume / customer enumeration", "Medium", e["_ts"], agent,
                                  f"{calls} calls, {distinct} distinct customers in {c['volume_window_min']} min",
                                  "T1119 / OWASP-LLM06"))
                last_alert = e["_ts"]
    return out


def d11_injection_then_side_effect(events, cfg):
    ro = set(cfg["agent"]["read_only_tools"])
    follow = timedelta(seconds=cfg["injection_followup_sec"])
    flagged = {}
    out = []
    for e in events:
        if e["source"] == "llm" and e["event"] == "retrieval" and e.get("injection_flag"):
            flagged[e["session"]] = e["_ts"]
        elif e["source"] == "agent" and e["event"] == "tool_call" and e.get("session") in flagged:
            if e["tool"] not in ro and e["_ts"] - flagged[e["session"]] <= follow:
                out.append(_alert("D11", "Injection indicator followed by side-effect tool call", "High",
                                  e["_ts"], e["actor"], f"tool={e['tool']} within {cfg['injection_followup_sec']}s "
                                  f"of flagged retrieval (session {e['session']})", "OWASP-LLM01"))
                del flagged[e["session"]]
    return out


# ----------------------------------------------------------------------------
# D12 - D16 : control failure, secrets, PHI-in-logs, cost abuse
# ----------------------------------------------------------------------------

def d12_log_source_silence(events, cfg):
    gap = timedelta(minutes=cfg["log_silence_min"])
    hb = defaultdict(list)
    for e in events:
        if e["source"] == "log_pipeline" and e["event"] == "heartbeat":
            hb[e["log_source"]].append(e["_ts"])
    end = events[-1]["_ts"]
    out = []
    for src, times in hb.items():
        for a, b in zip(times, times[1:]):
            if b - a >= gap:
                out.append(_alert("D12", "Log source went silent", "High", a + gap, src,
                                  f"no events from {src} for {int((b - a).total_seconds() // 60)} min", "T1562"))
        if end - times[-1] >= gap:
            out.append(_alert("D12", "Log source went silent", "High", times[-1] + gap, src,
                              f"no events from {src} until end of data", "T1562"))
    return out


def d13_security_control_disabled(events, cfg):
    bad = set(cfg["control_disabled_events"])
    return [_alert("D13", "Security control disabled or weakened", "Critical", e["_ts"], e["actor"],
                   f"{e['event']} on {e.get('resource', 'n/a')}", "T1562")
            for e in events if e["source"] == "cloud" and e["event"] in bad]


def d14_secret_committed(events, cfg):
    return [_alert("D14", "Secret detected in pushed commit", "High", e["_ts"], e["actor"],
                   f"{e['secret_findings']} finding(s) in {e.get('repo')}", "T1552")
            for e in events if e["source"] == "git" and e["event"] == "push" and e.get("secret_findings", 0) > 0]


# Patterns need context words to keep false positives down (random 10-digit numbers are common).
# Checksum validation of national IDs should be added after confirming the official algorithm.
PHI_PATTERNS = {
    "national_id_ctx": re.compile(r"(?i)\b(?:national[_ ]?id|iqama|nid)\W{0,3}([12]\d{9})\b"),
    "mrn_ctx": re.compile(r"(?i)\bmrn\W{0,3}(\d{6,10})\b"),
}


def d15_phi_in_logs(events, cfg):
    out = []
    for e in events:
        if e["source"] in ("app_log", "prompt_log") and e["event"] in ("log_line", "prompt_logged"):
            for name, rx in PHI_PATTERNS.items():
                m = rx.search(e.get("message", ""))
                if m:
                    masked = "*" * (len(m.group(1)) - 3) + m.group(1)[-3:]
                    out.append(_alert("D15", "PHI pattern found in application/prompt logs", "High", e["_ts"],
                                      e.get("actor", "app"), f"pattern={name} value={masked}", "OWASP-LLM02",
                                      log_source=e["source"]))
                    break
    return out


def d16_denial_of_wallet(events, cfg):
    c = cfg["wallet"]
    win = timedelta(minutes=c["window_min"])
    by_tenant = defaultdict(list)
    for e in events:
        if e["source"] == "llm" and e["event"] == "completion":
            by_tenant[e["tenant"]].append(e)
    out = []
    for tenant, evs in by_tenant.items():
        dq: deque = deque()
        total = 0
        last_alert = None
        for e in evs:
            dq.append((e["_ts"], e["tokens"]))
            total += e["tokens"]
            while e["_ts"] - dq[0][0] > win:
                total -= dq.popleft()[1]
            if total > c["tenant_token_cap"] and (last_alert is None or e["_ts"] - last_alert > win):
                out.append(_alert("D16", "LLM token spend spike (denial-of-wallet)", "Medium", e["_ts"], tenant,
                                  f"{total} tokens in {c['window_min']} min (cap {c['tenant_token_cap']})", "OWASP-LLM10"))
                last_alert = e["_ts"]
    return out


# ----------------------------------------------------------------------------
# registry
# ----------------------------------------------------------------------------

RULE_CATALOG = [
    ("D01", "Brute force followed by successful login", "Suspicious access", "T1110", "High"),
    ("D02", "Privileged login without MFA", "Suspicious access", "T1078", "High"),
    ("D03", "Privileged role granted outside approved change", "Privilege change", "T1098", "High"),
    ("D04", "Burst account creation", "Privilege change", "T1136", "High"),
    ("D05", "Service account used from previously unseen network", "Credential use", "T1078.004", "High"),
    ("D06", "Mass record access", "Data exfiltration", "T1213", "High"),
    ("D07", "Bulk read followed by egress to unapproved destination", "Data exfiltration", "T1041", "Critical"),
    ("D08", "Egress to unapproved destination", "Data exfiltration", "T1048", "Medium/High"),
    ("D09", "Agent called prohibited / unapproved high-risk tool", "Anomalous agent action", "OWASP-LLM06", "High/Critical"),
    ("D10", "Agent anomalous volume / customer enumeration", "Anomalous agent action", "T1119 / OWASP-LLM06", "Medium"),
    ("D11", "Injection indicator followed by side-effect tool call", "Anomalous agent action", "OWASP-LLM01", "High"),
    ("D12", "Log source went silent", "Security-control failure", "T1562", "High"),
    ("D13", "Security control disabled or weakened", "Security-control failure", "T1562", "Critical"),
    ("D14", "Secret detected in pushed commit", "Credential use", "T1552", "High"),
    ("D15", "PHI pattern found in application/prompt logs", "Data protection failure", "OWASP-LLM02", "High"),
    ("D16", "LLM token spend spike (denial-of-wallet)", "Cost / availability abuse", "OWASP-LLM10", "Medium"),
]


def run_all(events: list[dict], cfg: dict) -> list[dict]:
    alerts: list[dict] = []
    alerts += d01_bruteforce_then_success(events, cfg)
    alerts += d02_privileged_login_no_mfa(events, cfg)
    alerts += d03_priv_grant_outside_change(events, cfg)
    alerts += d04_burst_account_creation(events, cfg)
    alerts += d05_service_account_new_network(events, cfg)
    d06 = d06_mass_record_access(events, cfg)
    alerts += d06
    alerts += d07_bulk_read_then_egress(events, cfg, d06)
    alerts += d08_egress_unapproved(events, cfg)
    alerts += d09_agent_tool_policy_violation(events, cfg)
    alerts += d10_agent_volume_enumeration(events, cfg)
    alerts += d11_injection_then_side_effect(events, cfg)
    alerts += d12_log_source_silence(events, cfg)
    alerts += d13_security_control_disabled(events, cfg)
    alerts += d14_secret_committed(events, cfg)
    alerts += d15_phi_in_logs(events, cfg)
    alerts += d16_denial_of_wallet(events, cfg)
    alerts.sort(key=lambda a: a["ts"])
    return alerts
