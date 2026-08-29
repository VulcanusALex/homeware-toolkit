---
name: Hardware testing call
about: Volunteer to test a speculative device driver on your own gateway
title: '[hardware-test] '
labels: hardware-test, untested-driver
assignees: ''

---

## Device under test

| Field | Value |
|---|---|
| ISP / country | <!-- e.g. Vodafone UK --> |
| Device model | <!-- e.g. Technicolor VCNT-I --> |
| Board | <!-- e.g. VCNT-I --> |
| Firmware | <!-- exact version from web UI --> |
| Driver name | <!-- e.g. vcnt_i --> |

## Steps

1. Install the latest toolkit: `pipx install nexxt-one-toolkit --force`
2. Run the read-only probe and paste the output:
   ```bash
   nexxt probe --report http://192.168.1.254
   ```
3. If the probe reports a matching board family, try login/auth:
   - For button-login devices: `nexxt session login`
   - For SRP6/password devices: please note that auth is not implemented yet; just confirm the login method your UI uses.
4. If authenticated, run:
   ```bash
   nexxt verify
   nexxt doctor --key ~/.nexxt-one-toolkit/id_rsa
   ```
5. (Optional) If you are comfortable, try SSH bootstrap and report success/failure:
   ```bash
   nexxt setup
   ```

## What to include

- Full output of `nexxt probe --report` (no credentials, MACs, serials).
- Whether `nexxt verify` reports `CONFIRMED` or `NOT CONFIRMED`.
- Any errors or unexpected behaviour.
- Confirmation that this is **your own device**.

## Safety reminder

Only run tests on a gateway you own. The toolkit never flashes firmware or
changes TR-069, but speculative drivers may still behave differently on your
specific firmware revision. Use `nexxt ssh teardown` to roll back if you
reached the SSH bootstrap step.
