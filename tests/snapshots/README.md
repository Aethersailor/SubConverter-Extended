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
