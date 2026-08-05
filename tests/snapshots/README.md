# SubConverter Smoke Snapshots

This directory can hold optional golden outputs for
`scripts/run-subconverter-smoke.py`.

Create or refresh snapshots against a running instance:

```bash
python3 scripts/run-subconverter-smoke.py \
  --base-url http://127.0.0.1:25500 \
  --snapshot-dir tests/snapshots \
  --update-snapshots
```

Run comparison without updating:

```bash
python3 scripts/run-subconverter-smoke.py \
  --base-url http://127.0.0.1:25500 \
  --snapshot-dir tests/snapshots
```

The committed `compatibility/` snapshots are the offline first-round
compatibility baseline. They are generated from the synthetic subscription and
ruleset server in `tests/compatibility_security_baseline.py`; dynamic fixture
ports and provider hashes are normalized before comparison. For formats whose
default base templates differ by platform, the committed Golden keeps the
generated provider, proxy, or outbound record while separate semantic checks
still inspect the complete response.

Refresh them only after reviewing the output change:

```bash
python3 tests/compatibility_security_baseline.py \
  --binary build/subconverter \
  --update-golden
```

Normal `full` test runs compare the current output to these files and never
update them.
