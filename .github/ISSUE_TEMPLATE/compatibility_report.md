---
name: Compatibility report
about: Report probe results from a different firmware/board
title: "[compat] "
labels: compatibility
---

**Device**
- Product (e.g. NeXXt One FGA221DFWB):
- Board (e.g. GDNT-S):
- Firmware version (from sysinfo):

**Sanitized support bundle**

Run `./homeware support-bundle` and attach the resulting ZIP after reviewing
`report.json`. It excludes session credentials, keys, MACs, serials and raw
IPv4 addresses by design.

**Does the injection verification (`./homeware verify`) succeed?**
yes / no / not tried
