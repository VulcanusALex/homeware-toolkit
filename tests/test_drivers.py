"""Tests for the device driver / capability abstraction."""

from __future__ import annotations

import unittest

from homeware_toolkit import compat, driver, drivers


class DriverRegistryTest(unittest.TestCase):
    def test_nexxt_driver_is_registered(self):
        factory = drivers.get("nexxt")
        dev = factory(None)
        self.assertEqual(dev.name, "nexxt")
        self.assertEqual(dev.cap("injection", "service"), "pingstatus")

    def test_openwrt_driver_is_registered(self):
        factory = drivers.get("openwrt")
        dev = factory(None)
        self.assertEqual(dev.name, "openwrt")
        self.assertEqual(dev.cap("wan", "wan4_interface"), "eth1")
        self.assertEqual(dev.cap("wan", "lan6_interface"), "br-lan")
        # Inherits NeXXt defaults where not overridden.
        self.assertEqual(dev.cap("injection", "service"), "pingstatus")
        self.assertEqual(dev.cap("firewall", "backend"), "uci")

    def test_vcnt_i_driver_is_registered(self):
        factory = drivers.get("vcnt_i")
        dev = factory(None)
        self.assertEqual(dev.name, "vcnt_i")
        self.assertEqual(dev.cap("auth", "method"), "srp6")
        self.assertEqual(dev.cap("wan", "wan4_interface"), "eth4")
        # Inherits NeXXt defaults where not overridden.
        self.assertEqual(dev.cap("injection", "service"), "pingstatus")

    def test_unknown_driver_falls_back_to_nexxt(self):
        factory = drivers.get("does_not_exist")
        dev = factory(None)
        self.assertEqual(dev.name, "nexxt")

    def test_make_device_dispatches_by_name(self):
        dev = drivers.make_device("openwrt")
        self.assertEqual(dev.name, "openwrt")


class CapabilityMergingTest(unittest.TestCase):
    def test_entry_capabilities_merge_defaults(self):
        entry = {
            "board": "TEST",
            "model_prefix": "TEST",
            "product_contains": "TEST",
            "driver": "nexxt",
            "capabilities": {
                "wan": {"wan4_interface": "wan"},
            },
        }
        caps = compat.entry_capabilities(entry)
        self.assertEqual(caps["wan"]["wan4_interface"], "wan")
        # Other WAN key stays default.
        self.assertEqual(caps["wan"]["lan6_interface"], "br-lan")
        # Other sections stay default.
        self.assertEqual(caps["injection"]["service"], "pingstatus")

    def test_default_device(self):
        dev = driver.default_device()
        self.assertEqual(dev.name, "nexxt")
        self.assertEqual(dev.cap("ssh", "instance"), "nx")


if __name__ == "__main__":
    unittest.main()
