"""Hardware-free tests for declarative config management (apply.py).

Device interaction is faked: ``FakeFW`` implements the same in-memory
ensure/delete/list_rules semantics as firewall.FW, and ``run`` answers the
read_ssh_state probes from canned text.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from home_gateway_toolkit import apply as apply_mod
from home_gateway_toolkit.apply import (ConfigError, apply_plan, load_config, plan,
                                 read_ssh_state, run_apply, run_diff)
from home_gateway_toolkit.firewall import FW

GOOD_UCI = ("dropbear.nx=dropbear\n"
            "dropbear.nx.enable='1'\n"
            "dropbear.nx.Port='2222'\n"
            "dropbear.nx.Interface='lan'\n"
            "dropbear.nx.PasswordAuth='off'\n"
            "dropbear.nx.RootPasswordAuth='off'\n")


class FakeFW:
    """In-memory stand-in for firewall.FW."""

    def __init__(self, rules=None, fail_on=None, uci=GOOD_UCI, has_key=True):
        self.rules = [dict(r) for r in (rules or [])]
        self.calls = []
        self.fail_on = fail_on
        self.uci = uci
        self.has_key = has_key

    def list_rules(self):
        return [dict(r) for r in self.rules]

    def ensure(self, name, proto, dest_ip, dest_port, family, src, dest):
        self.calls.append(("ensure", name))
        if self.fail_on == name:
            raise RuntimeError("simulated device failure")
        desired = FW._desired(name, proto, dest_ip, dest_port, family, src, dest)
        matches = [r for r in self.rules if r.get("name") == name]
        if matches:
            current = matches[0]
            changed = any(current.get(k, "any" if k == "family" else "") != v
                          for k, v in desired.items())
            section = current["section"]
        else:
            changed = True
            section = f"cfg{len(self.rules):02d}"
            self.rules.append({"section": section})
        if changed:
            self.rules[[r["section"] for r in self.rules].index(section)] \
                .update(desired)
        return {"name": name, "changed": changed, "section": section}

    def delete(self, name):
        self.calls.append(("delete", name))
        sections = [r["section"] for r in self.rules if r.get("name") == name]
        self.rules = [r for r in self.rules if r.get("name") != name]
        return sections

    def run(self, cmd):
        self.calls.append(("run", cmd))
        if cmd.startswith("uci show dropbear.nx"):
            return self.uci
        return "yes\n" if self.has_key else "no\n"


def device_rule(name="Allow-AWG-v6", section="cfg01", **over):
    rule = {"section": section, "name": name, "src": "wan", "dest": "lan",
            "proto": "udp", "family": "ipv6", "dest_ip": "2001:db8::123",
            "dest_port": "51820", "target": "ACCEPT", "enabled": "1"}
    rule.update(over)
    return rule


def write_config(data):
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(data, handle)
    handle.close()
    return handle.name


def base_config(**over):
    data = {"version": 1,
            "firewall": {"rules": [
                {"name": "Allow-AWG-v6", "proto": "udp",
                 "dest_ip": "2001:db8::123", "dest_port": 51820}]}}
    data.update(over)
    return data


class LoadConfigTest(unittest.TestCase):
    def tearDown(self):
        if getattr(self, "_path", None):
            os.unlink(self._path)

    def load(self, data):
        self._path = write_config(data)
        return load_config(self._path)

    def test_valid_config_normalizes(self):
        config = self.load(base_config())
        rule = config.firewall_rules[0]
        self.assertEqual(rule["dest_port"], "51820")  # int -> str
        self.assertEqual(rule["family"], "ipv6")      # defaults
        self.assertEqual((rule["src"], rule["dest"]), ("wan", "lan"))
        self.assertFalse(config.firewall_prune)
        self.assertEqual(config.ssh, {})

    def test_dest_ip_is_normalized(self):
        config = self.load(base_config())
        config.firewall_rules  # noqa - sanity
        path = write_config({"version": 1, "firewall": {"rules": [
            {"name": "x", "proto": "tcp",
             "dest_ip": "2001:0db8:0000::0001", "dest_port": "80"}]}})
        self._path, path = path, self._path
        os.unlink(path)
        config = load_config(self._path)
        self.assertEqual(config.firewall_rules[0]["dest_ip"], "2001:db8::1")

    def test_example_file_is_valid(self):
        here = os.path.dirname(os.path.abspath(__file__))
        config = load_config(os.path.join(here, "..", "examples", "home_gateway.json"))
        self.assertEqual(len(config.firewall_rules), 2)
        self.assertEqual(config.ssh,
                         {"require_key_only": True, "require_lan_only": True})

    def test_missing_version(self):
        with self.assertRaisesRegex(ConfigError, r"^version:"):
            self.load({"firewall": {}})

    def test_wrong_version(self):
        with self.assertRaisesRegex(ConfigError, r"^version:.*unsupported"):
            self.load({"version": 2})

    def test_version_must_be_int(self):
        with self.assertRaisesRegex(ConfigError, r"^version:"):
            self.load({"version": "1"})

    def test_top_level_must_be_object(self):
        with self.assertRaisesRegex(ConfigError, r"^\$:"):
            self.load([1, 2])

    def test_missing_rule_field(self):
        data = base_config()
        del data["firewall"]["rules"][0]["dest_port"]
        with self.assertRaisesRegex(ConfigError,
                                    r"firewall\.rules\[0\]\.dest_port"):
            self.load(data)

    def test_bad_dest_ip(self):
        data = base_config()
        data["firewall"]["rules"][0]["dest_ip"] = "1.2.3.4; reboot"
        with self.assertRaisesRegex(ConfigError,
                                    r"firewall\.rules\[0\]\.dest_ip"):
            self.load(data)

    def test_bad_dest_port(self):
        data = base_config()
        data["firewall"]["rules"][0]["dest_port"] = 70000
        with self.assertRaisesRegex(ConfigError,
                                    r"firewall\.rules\[0\]\.dest_port"):
            self.load(data)

    def test_dest_port_bool_rejected(self):
        data = base_config()
        data["firewall"]["rules"][0]["dest_port"] = True
        with self.assertRaisesRegex(ConfigError,
                                    r"firewall\.rules\[0\]\.dest_port"):
            self.load(data)

    def test_bad_proto(self):
        data = base_config()
        data["firewall"]["rules"][0]["proto"] = "udp; x"
        with self.assertRaisesRegex(ConfigError,
                                    r"firewall\.rules\[0\]\.proto"):
            self.load(data)

    def test_bad_name(self):
        data = base_config()
        data["firewall"]["rules"][0]["name"] = "x'; reboot; '"
        with self.assertRaisesRegex(ConfigError,
                                    r"firewall\.rules\[0\]\.name"):
            self.load(data)

    def test_duplicate_rule_names(self):
        data = base_config()
        data["firewall"]["rules"].append(dict(data["firewall"]["rules"][0]))
        with self.assertRaisesRegex(ConfigError, "duplicate rule name"):
            self.load(data)

    def test_enabled_false_rejected(self):
        data = base_config()
        data["firewall"]["rules"][0]["enabled"] = False
        with self.assertRaisesRegex(ConfigError,
                                    r"firewall\.rules\[0\]\.enabled"):
            self.load(data)

    def test_prune_must_be_bool(self):
        with self.assertRaisesRegex(ConfigError, r"^firewall\.prune:"):
            self.load({"version": 1, "firewall": {"prune": "yes"}})

    def test_unknown_keys_warn_but_load(self):
        data = base_config(future_feature={"x": 1})
        data["firewall"]["rules"][0]["extra"] = True
        config = self.load(data)
        self.assertEqual(len(config.firewall_rules), 1)
        self.assertTrue(any("future_feature" in w for w in config.warnings))
        self.assertTrue(any("extra" in w for w in config.warnings))

    def test_file_not_found(self):
        with self.assertRaisesRegex(ConfigError, "file not found"):
            load_config("/nonexistent/nexxt.json")

    def test_invalid_json(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        handle.write("{not json")
        handle.close()
        self._path = handle.name
        with self.assertRaisesRegex(ConfigError, "invalid JSON"):
            load_config(self._path)


class PlanTest(unittest.TestCase):
    def config(self, **over):
        path = write_config(base_config(**over))
        self.addCleanup(os.unlink, path)
        return load_config(path)

    def ops_of(self, plan_dict, op):
        return [item for item in plan_dict["ops"] if item["op"] == op]

    def test_empty_device_all_create(self):
        p = plan(self.config(), [])
        self.assertEqual([item["op"] for item in p["ops"]], ["CREATE"])
        self.assertEqual(p["summary"]["create"], 1)
        self.assertEqual(p["pending_changes"], 1)

    def test_exact_match_is_noop(self):
        p = plan(self.config(), [device_rule()])
        self.assertEqual([item["op"] for item in p["ops"]], ["NOOP"])
        self.assertEqual(p["pending_changes"], 0)

    def test_field_difference_is_update(self):
        p = plan(self.config(), [device_rule(dest_port="51821")])
        (item,) = self.ops_of(p, "UPDATE")
        self.assertEqual(item["details"]["changes"]["dest_port"],
                         ["51821", "51820"])

    def test_missing_family_defaults_to_any(self):
        rule = device_rule()
        del rule["family"]  # device rule without family means "any"
        p = plan(self.config(), [rule])
        (item,) = self.ops_of(p, "UPDATE")
        self.assertEqual(item["details"]["changes"]["family"],
                         ["any", "ipv6"])

    def test_extra_rule_not_pruned_by_default(self):
        rules = [device_rule(), device_rule(name="Other-Rule", section="cfg02")]
        p = plan(self.config(), rules)
        self.assertEqual(self.ops_of(p, "DELETE"), [])
        self.assertEqual([item["op"] for item in p["ops"]], ["NOOP"])

    def test_prune_true_deletes_toolkit_managed_extra(self):
        rules = [device_rule(), device_rule(name="Other-Rule", section="cfg02")]
        p = plan(self.config(firewall={"prune": True, "rules":
                                       base_config()["firewall"]["rules"]}),
                 rules)
        (item,) = self.ops_of(p, "DELETE")
        self.assertEqual(item["details"]["name"], "Other-Rule")

    def test_prune_never_deletes_foreign_shapes(self):
        foreign = {"section": "cfg09", "name": "ISP-Rule", "src": "wan",
                   "target": "ACCEPT", "proto": "all"}  # no dest_ip/dest_port
        p = plan(self.config(firewall={"prune": True, "rules":
                                       base_config()["firewall"]["rules"]}),
                 [device_rule(), foreign])
        self.assertEqual(self.ops_of(p, "DELETE"), [])

    def test_ssh_assertions_pass(self):
        config = self.config(ssh={"require_key_only": True,
                                  "require_lan_only": True})
        state = {"instance": True, "authorized_keys": True,
                 "key_only": True, "lan_only": True}
        p = plan(config, [], state)
        kinds = [item["op"] for item in p["ops"]]
        self.assertEqual(kinds, ["CREATE", "CHECK_PASS", "CHECK_PASS"])
        self.assertTrue(p["ok"])

    def test_ssh_assertion_failure(self):
        config = self.config(ssh={"require_lan_only": True})
        state = {"instance": True, "authorized_keys": True,
                 "key_only": True, "lan_only": False}
        p = plan(config, [], state)
        (item,) = self.ops_of(p, "CHECK_FAIL")
        self.assertEqual(item["details"]["check"], "require_lan_only")
        self.assertFalse(p["ok"])

    def test_duplicate_device_rules_fail_check(self):
        rules = [device_rule(), device_rule(section="cfg02")]
        p = plan(self.config(), rules)
        (item,) = self.ops_of(p, "CHECK_FAIL")
        self.assertIn("duplicate", item["description"])
        self.assertFalse(p["ok"])

    def test_ssh_section_requires_state(self):
        config = self.config(ssh={"require_key_only": True})
        with self.assertRaisesRegex(RuntimeError, "ssh_state"):
            plan(config, [])


class ApplyPlanTest(unittest.TestCase):
    def config(self, **over):
        path = write_config(base_config(**over))
        self.addCleanup(os.unlink, path)
        return load_config(path)

    def test_success_path_applies_all(self):
        fw = FakeFW()
        p = plan(self.config(), fw.list_rules())
        result = apply_plan(p, fw)
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["applied"]), 1)
        self.assertEqual(result["applied"][0]["result"]["changed"], True)
        self.assertEqual(fw.rules[0]["name"], "Allow-AWG-v6")

    def test_failure_stops_and_reports(self):
        rules_cfg = [
            {"name": "First", "proto": "udp", "dest_ip": "2001:db8::1",
             "dest_port": 1000},
            {"name": "Boom", "proto": "udp", "dest_ip": "2001:db8::1",
             "dest_port": 1001},
            {"name": "Never", "proto": "udp", "dest_ip": "2001:db8::1",
             "dest_port": 1002}]
        path = write_config({"version": 1, "firewall": {"rules": rules_cfg}})
        self.addCleanup(os.unlink, path)
        config = load_config(path)
        fw = FakeFW(fail_on="Boom")
        p = plan(config, fw.list_rules())
        result = apply_plan(p, fw)
        self.assertFalse(result["ok"])
        self.assertEqual([item["details"]["name"] for item in result["applied"]],
                         ["First"])
        self.assertEqual(result["failed"]["details"]["name"], "Boom")
        self.assertIn("simulated device failure", result["failed"]["error"])
        self.assertEqual([item["details"]["name"] for item in result["aborted"]],
                         ["Never"])
        self.assertEqual([r.get("name") for r in fw.rules], ["First"])

    def test_idempotent_second_run_is_all_noop(self):
        fw = FakeFW()
        config = self.config()
        first = apply_plan(plan(config, fw.list_rules()), fw)
        self.assertTrue(first["ok"])
        self.assertEqual(first["applied"][0]["op"], "CREATE")
        second_plan = plan(config, fw.list_rules())
        self.assertEqual([item["op"] for item in second_plan["ops"]], ["NOOP"])
        second = apply_plan(second_plan, fw)
        self.assertTrue(second["ok"])
        self.assertEqual(second["applied"], [])

    def test_check_fail_blocks_all_mutation(self):
        config = self.config(ssh={"require_key_only": True})
        state = {"instance": True, "authorized_keys": False,
                 "key_only": False, "lan_only": True}
        fw = FakeFW()
        p = plan(config, fw.list_rules(), state)
        result = apply_plan(p, fw)
        self.assertFalse(result["ok"])
        self.assertEqual(len(result["checks_failed"]), 1)
        self.assertEqual([c[0] for c in fw.calls], [])  # nothing ran
        self.assertEqual(fw.rules, [])

    def test_prune_delete_executes(self):
        extra = device_rule(name="Old-Rule", section="cfg02")
        fw = FakeFW([device_rule(), extra])
        config = self.config(firewall={"prune": True, "rules":
                                       base_config()["firewall"]["rules"]})
        p = plan(config, fw.list_rules())
        result = apply_plan(p, fw)
        self.assertTrue(result["ok"])
        self.assertEqual([item["op"] for item in result["applied"]], ["DELETE"])
        self.assertEqual([r.get("name") for r in fw.rules], ["Allow-AWG-v6"])


class SshStateTest(unittest.TestCase):
    def run_with(self, uci, has_key):
        return lambda cmd: (uci if cmd.startswith("uci show dropbear.nx")
                            else ("yes\n" if has_key else "no\n"))

    def test_healthy_state(self):
        state = read_ssh_state(self.run_with(GOOD_UCI, True))
        self.assertTrue(state["key_only"])
        self.assertTrue(state["lan_only"])
        self.assertTrue(state["instance"])

    def test_password_auth_on_fails_key_only(self):
        uci = GOOD_UCI.replace("PasswordAuth='off'", "PasswordAuth='on'")
        state = read_ssh_state(self.run_with(uci, True))
        self.assertFalse(state["key_only"])
        self.assertTrue(state["lan_only"])

    def test_wan_interface_fails_lan_only(self):
        uci = GOOD_UCI.replace("Interface='lan'", "Interface='wan'")
        state = read_ssh_state(self.run_with(uci, True))
        self.assertFalse(state["lan_only"])

    def test_missing_key_fails_key_only(self):
        state = read_ssh_state(self.run_with(GOOD_UCI, False))
        self.assertFalse(state["key_only"])

    def test_no_instance(self):
        state = read_ssh_state(self.run_with("", False))
        self.assertEqual(state, {"instance": False, "authorized_keys": False,
                                 "key_only": False, "lan_only": False})


class CliEntryTest(unittest.TestCase):
    def config_path(self, **over):
        path = write_config(base_config(**over))
        self.addCleanup(os.unlink, path)
        return path

    def test_diff_reports_pending_changes(self):
        fw = FakeFW()
        p, code = run_diff(fw, self.config_path())
        self.assertEqual(code, 2)
        self.assertEqual(p["summary"]["create"], 1)

    def test_diff_in_sync(self):
        fw = FakeFW([device_rule()])
        p, code = run_diff(fw, self.config_path())
        self.assertEqual(code, 0)
        self.assertEqual([item["op"] for item in p["ops"]], ["NOOP"])

    def test_diff_check_fail(self):
        fw = FakeFW(uci=GOOD_UCI.replace("Interface='lan'",
                                         "Interface='wan'"))
        p, code = run_diff(fw, self.config_path(
            ssh={"require_lan_only": True}))
        self.assertEqual(code, 1)
        self.assertFalse(p["ok"])

    def test_apply_end_to_end(self):
        fw = FakeFW()
        path = self.config_path(ssh={"require_key_only": True})
        result, code = run_apply(fw, path)
        self.assertEqual(code, 0)
        self.assertTrue(result["ok"])
        self.assertEqual(fw.rules[0]["name"], "Allow-AWG-v6")
        # Second apply: fully converged, nothing to do.
        result2, code2 = run_apply(fw, path)
        self.assertEqual(code2, 0)
        self.assertEqual(result2["applied"], [])

    def test_render_plan_text(self):
        fw = FakeFW()
        config = load_config(self.config_path())
        text = apply_mod.render_plan(apply_mod.gather_plan(config, fw))
        self.assertIn("[+] rule 'Allow-AWG-v6': create", text)
        self.assertIn("1 to create", text)


if __name__ == "__main__":
    unittest.main()
