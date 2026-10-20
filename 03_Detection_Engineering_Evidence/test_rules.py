"""
Unit tests for the 16 detection rules.  Run:  python -m unittest -v test_rules
Each rule has at least one positive case (must alert) and one negative case (must NOT alert).
Boundary cases check thresholds are strict/inclusive exactly as documented.
"""
import unittest
from datetime import datetime, timedelta, timezone

import engine

CFG = engine.load_config("config.json")
T0 = datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc)


def E(offset_s, source, event, **kw):
    ts = T0 + timedelta(seconds=offset_s)
    d = {"ts": ts.isoformat(), "_ts": ts, "source": source, "event": event}
    d.update(kw)
    return d


def run(rule, events, *extra):
    events = sorted(events, key=lambda e: e["_ts"])
    return rule(events, CFG, *extra)


def logins(n_fail, ip="198.51.100.9", user="u1", gap=5, success=True, mfa=True, role="user"):
    ev = [E(i * gap, "auth", "login", actor=user, actor_type="human", role=role, outcome="failure", ip=ip, mfa=None)
          for i in range(n_fail)]
    if success:
        ev.append(E(n_fail * gap + 5, "auth", "login", actor=user, actor_type="human", role=role, outcome="success",
                    ip=ip, mfa=mfa))
    return ev


class TestIdentity(unittest.TestCase):
    def test_d01_positive(self):
        self.assertEqual(len(run(engine.d01_bruteforce_then_success, logins(12))), 1)

    def test_d01_negative_few_failures(self):
        self.assertEqual(run(engine.d01_bruteforce_then_success, logins(3)), [])

    def test_d01_negative_failures_without_success(self):
        self.assertEqual(run(engine.d01_bruteforce_then_success, logins(30, success=False)), [])

    def test_d01_boundary_threshold(self):
        self.assertEqual(len(run(engine.d01_bruteforce_then_success, logins(10))), 1)
        self.assertEqual(run(engine.d01_bruteforce_then_success, logins(9)), [])

    def test_d01_negative_slow_failures(self):
        # 12 failures spread over an hour never reach 10 inside 5 minutes
        self.assertEqual(run(engine.d01_bruteforce_then_success, logins(12, gap=300)), [])

    def test_d01_negative_failures_spread_beyond_5min_window(self):
        # 12 failures at 60s spacing (12 min span): >=10 in the 15-min look-back but never >=10 inside 5 min
        self.assertEqual(run(engine.d01_bruteforce_then_success, logins(12, gap=60)), [])

    def test_d02_positive(self):
        ev = [E(0, "auth", "login", actor="a", role="Admin", outcome="success", mfa=False, ip="10.0.0.1")]
        self.assertEqual(len(run(engine.d02_privileged_login_no_mfa, ev)), 1)

    def test_d02_negative_mfa_true(self):
        ev = [E(0, "auth", "login", actor="a", role="Admin", outcome="success", mfa=True, ip="10.0.0.1")]
        self.assertEqual(run(engine.d02_privileged_login_no_mfa, ev), [])

    def test_d02_negative_standard_user_no_mfa_is_not_this_rule(self):
        ev = [E(0, "auth", "login", actor="u", role="user", outcome="success", mfa=False, ip="10.0.0.1")]
        self.assertEqual(run(engine.d02_privileged_login_no_mfa, ev), [])

    def test_d02_negative_failed_login(self):
        ev = [E(0, "auth", "login", actor="a", role="Admin", outcome="failure", mfa=False, ip="10.0.0.1")]
        self.assertEqual(run(engine.d02_privileged_login_no_mfa, ev), [])

    def test_d03_positive_no_ticket(self):
        ev = [E(0, "cloud", "role_grant", actor="a", target="x", role="Admin", change_ticket=None, approver=None)]
        self.assertEqual(len(run(engine.d03_priv_grant_outside_change, ev)), 1)

    def test_d03_positive_self_approved(self):
        ev = [E(0, "cloud", "role_grant", actor="a", target="x", role="Owner", change_ticket="CHG-1", approver="a")]
        self.assertEqual(len(run(engine.d03_priv_grant_outside_change, ev)), 1)

    def test_d03_negative_approved(self):
        ev = [E(0, "cloud", "role_grant", actor="a", target="x", role="Admin", change_ticket="CHG-1", approver="b")]
        self.assertEqual(run(engine.d03_priv_grant_outside_change, ev), [])

    def test_d03_negative_non_privileged_role(self):
        ev = [E(0, "cloud", "role_grant", actor="a", target="x", role="Reader", change_ticket=None, approver=None)]
        self.assertEqual(run(engine.d03_priv_grant_outside_change, ev), [])

    def test_d04_positive_and_boundary(self):
        mk = lambda n: [E(i * 30, "cloud", "user_create", actor="a", target=f"t{i}") for i in range(n)]
        self.assertEqual(len(run(engine.d04_burst_account_creation, mk(5))), 1)
        self.assertEqual(run(engine.d04_burst_account_creation, mk(4)), [])

    def test_d04_negative_slow_creation(self):
        ev = [E(i * 900, "cloud", "user_create", actor="a", target=f"t{i}") for i in range(8)]
        self.assertEqual(run(engine.d04_burst_account_creation, ev), [])

    def _svc_events(self, later_ip):
        base = [E(i * 600, "auth", "token_issued", actor="svc-a", actor_type="service", ip="10.0.1.%d" % (10 + i % 5))
                for i in range(6)]
        late = E(13 * 3600, "auth", "token_issued", actor="svc-a", actor_type="service", ip=later_ip)
        return base + [late]

    def test_d05_positive_new_network(self):
        self.assertEqual(len(run(engine.d05_service_account_new_network, self._svc_events("198.51.100.77"))), 1)

    def test_d05_negative_same_subnet_new_ip(self):
        self.assertEqual(run(engine.d05_service_account_new_network, self._svc_events("10.0.1.99")), [])


class TestDataAccess(unittest.TestCase):
    def reads(self, actor, per_call, calls, gap_s, atype="service"):
        return [E(i * gap_s, "api", "record_read", actor=actor, actor_type=atype, records=per_call, ip="10.0.0.1")
                for i in range(calls)]

    def test_d06_positive_service(self):
        a = run(engine.d06_mass_record_access, self.reads("svc-x", 500, 50, 14))
        self.assertEqual(len(a), 1)

    def test_d06_alert_fires_when_threshold_crossed_not_at_end(self):
        a = run(engine.d06_mass_record_access, self.reads("svc-x", 500, 50, 14))
        self.assertLess(a[0]["records_in_window"], 5600)  # fired at ~5,000, not after 25,000

    def test_d06_negative_below_threshold(self):
        self.assertEqual(run(engine.d06_mass_record_access, self.reads("svc-x", 100, 40, 14)), [])

    def test_d06_boundary_strictly_greater(self):
        self.assertEqual(run(engine.d06_mass_record_access, self.reads("svc-x", 500, 10, 10)), [])  # exactly 5000
        self.assertEqual(len(run(engine.d06_mass_record_access, self.reads("svc-x", 501, 10, 10))), 1)

    def test_d06_human_threshold_is_lower(self):
        self.assertEqual(len(run(engine.d06_mass_record_access, self.reads("dr.a", 1, 320, 1, "human"))), 1)
        self.assertEqual(run(engine.d06_mass_record_access, self.reads("dr.a", 1, 45, 10, "human")), [])

    def test_d06_per_actor_override(self):
        # svc-report-batch has override 3000: 2,700 must not alert, 3,200 must
        self.assertEqual(run(engine.d06_mass_record_access, self.reads("svc-report-batch", 450, 6, 120)), [])
        self.assertEqual(len(run(engine.d06_mass_record_access, self.reads("svc-report-batch", 640, 5, 60))), 1)

    def test_d07_positive(self):
        ev = self.reads("svc-x", 500, 50, 14) + [E(1200, "egress", "connection", actor="svc-x", dst_ip="203.0.113.45",
                                                    dst_port=443, bytes=5)]
        d06 = run(engine.d06_mass_record_access, ev)
        self.assertEqual(len(run(engine.d07_bulk_read_then_egress, ev, d06)), 1)

    def test_d07_negative_allowlisted_destination(self):
        ev = self.reads("svc-x", 500, 50, 14) + [E(1200, "egress", "connection", actor="svc-x", dst_ip="192.0.2.25",
                                                    dst_port=443, bytes=5)]
        d06 = run(engine.d06_mass_record_access, ev)
        self.assertEqual(run(engine.d07_bulk_read_then_egress, ev, d06), [])

    def test_d07_negative_egress_long_after(self):
        ev = self.reads("svc-x", 500, 50, 14) + [E(5 * 3600, "egress", "connection", actor="svc-x",
                                                    dst_ip="203.0.113.45", dst_port=443, bytes=5)]
        d06 = run(engine.d06_mass_record_access, ev)
        self.assertEqual(run(engine.d07_bulk_read_then_egress, ev, d06), [])

    def test_d08_positive_and_severity(self):
        ev = [E(0, "egress", "connection", actor="w", dst_ip="203.0.113.9", dst_port=443, bytes=10),
              E(10, "egress", "connection", actor="w2", dst_ip="203.0.113.10", dst_port=443, bytes=90_000_000)]
        a = run(engine.d08_egress_unapproved, ev)
        self.assertEqual(sorted(x["severity"] for x in a), ["High", "Medium"])

    def test_d08_negative_allowlisted(self):
        ev = [E(0, "egress", "connection", actor="w", dst_ip="198.51.100.10", dst_port=443, bytes=10)]
        self.assertEqual(run(engine.d08_egress_unapproved, ev), [])


class TestAgents(unittest.TestCase):
    def call(self, t, tool, **kw):
        base = dict(actor="agent-1", actor_type="agent", tool=tool, session="s1", customer="c1", approval_token=False)
        base.update(kw)
        return E(t, "agent", "tool_call", **base)

    def test_d09_prohibited_tool_even_with_approval(self):
        a = run(engine.d09_agent_tool_policy_violation, [self.call(0, "create_user", approval_token=True)])
        self.assertEqual((len(a), a[0]["severity"]), (1, "Critical"))

    def test_d09_unapproved_side_effect(self):
        self.assertEqual(len(run(engine.d09_agent_tool_policy_violation, [self.call(0, "issue_refund")])), 1)

    def test_d09_negative_approved_or_read_only(self):
        ev = [self.call(0, "issue_refund", approval_token=True), self.call(1, "search_customer")]
        self.assertEqual(run(engine.d09_agent_tool_policy_violation, ev), [])

    def test_d10_positive_volume(self):
        ev = [self.call(i * 5, "read_invoice") for i in range(35)]
        self.assertEqual(len(run(engine.d10_agent_volume_enumeration, ev)), 1)

    def test_d10_positive_enumeration(self):
        ev = [self.call(i * 5, "search_customer", customer=f"c{i}") for i in range(25)]
        self.assertEqual(len(run(engine.d10_agent_volume_enumeration, ev)), 1)

    def test_d10_negative_normal_busy_agent(self):
        ev = [self.call(i * 20, "search_customer", customer=f"c{i % 8}") for i in range(12)]
        self.assertEqual(run(engine.d10_agent_volume_enumeration, ev), [])

    def _inj(self, gap, tool):
        return [E(0, "llm", "retrieval", actor="agent-1", session="s1", injection_flag=True), self.call(gap, tool)]

    def test_d11_positive_side_effect_after_flag(self):
        self.assertEqual(len(run(engine.d11_injection_then_side_effect, self._inj(40, "update_customer"))), 1)

    def test_d11_negative_read_only_after_flag(self):
        self.assertEqual(run(engine.d11_injection_then_side_effect, self._inj(40, "search_customer")), [])

    def test_d11_negative_too_late(self):
        self.assertEqual(run(engine.d11_injection_then_side_effect, self._inj(600, "update_customer")), [])

    def test_d11_negative_no_flag(self):
        self.assertEqual(run(engine.d11_injection_then_side_effect, [self.call(5, "update_customer")]), [])


class TestControlsAndData(unittest.TestCase):
    def hb(self, src, start_min, end_min):
        return [E(m * 60, "log_pipeline", "heartbeat", log_source=src) for m in range(start_min, end_min)]

    def test_d12_positive_gap(self):
        ev = self.hb("api", 0, 10) + self.hb("api", 40, 50)
        a = run(engine.d12_log_source_silence, ev)
        self.assertEqual(len(a), 1)

    def test_d12_negative_short_gap(self):
        ev = self.hb("api", 0, 10) + self.hb("api", 20, 30)
        self.assertEqual(run(engine.d12_log_source_silence, ev), [])

    def test_d12_positive_silent_until_end_of_data(self):
        ev = self.hb("api", 0, 5) + self.hb("auth", 0, 40)
        a = run(engine.d12_log_source_silence, ev)
        self.assertEqual([x["actor"] for x in a], ["api"])

    def test_d13_positive_and_negative(self):
        pos = [E(0, "cloud", "audit_logging_disabled", actor="a", resource="trail")]
        neg = [E(0, "cloud", "waf_rule_updated", actor="a", resource="waf")]
        self.assertEqual(len(run(engine.d13_security_control_disabled, pos)), 1)
        self.assertEqual(run(engine.d13_security_control_disabled, neg), [])

    def test_d14_positive_and_negative(self):
        self.assertEqual(len(run(engine.d14_secret_committed, [E(0, "git", "push", actor="d", repo="r", secret_findings=2)])), 1)
        self.assertEqual(run(engine.d14_secret_committed, [E(0, "git", "push", actor="d", repo="r", secret_findings=0)]), [])

    def test_d15_positive_and_value_is_masked(self):
        ev = [E(0, "prompt_log", "prompt_logged", actor="s", message="summarise national_id: 1000000001 please")]
        a = run(engine.d15_phi_in_logs, ev)
        self.assertEqual(len(a), 1)
        self.assertNotIn("1000000001", str(a[0]))  # alert must not carry the raw identifier

    def test_d15_negative_number_without_context(self):
        ev = [E(0, "app_log", "log_line", actor="app", message="order_no 1234567890 phone 0501234567")]
        self.assertEqual(run(engine.d15_phi_in_logs, ev), [])

    def test_d16_positive_and_negative(self):
        hot = [E(i * 60, "llm", "completion", actor="g", tenant="t", tokens=20_000) for i in range(25)]
        calm = [E(i * 180, "llm", "completion", actor="g", tenant="t", tokens=2_000) for i in range(20)]
        self.assertEqual(len(run(engine.d16_denial_of_wallet, hot)), 1)
        self.assertEqual(run(engine.d16_denial_of_wallet, calm), [])


class TestEndToEnd(unittest.TestCase):
    def test_benign_day_has_zero_alerts(self):
        ev = engine.load_events("data/benign.jsonl")
        self.assertEqual(engine.run_all(ev, CFG), [])

    def test_every_rule_fires_on_attack_day(self):
        ev = engine.load_events("data/attack.jsonl")
        fired = {a["rule"] for a in engine.run_all(ev, CFG)}
        self.assertEqual(fired, {r[0] for r in engine.RULE_CATALOG})

    def test_alerts_contain_no_raw_patient_identifiers(self):
        ev = engine.load_events("data/attack.jsonl")
        blob = str(engine.run_all(ev, CFG))
        self.assertNotIn("1000000001", blob)
        self.assertNotIn("00123456", blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
