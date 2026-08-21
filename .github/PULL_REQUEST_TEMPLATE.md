<!-- Keep what applies, delete the rest. -->

## What this changes, and why

## Checklist

- [ ] **No real subscriber or customer data** anywhere in the diff — captures, logs, comments, test names, fixture file names. (`tests/test_no_real_subscriber_data.py` checks shape; it is not a substitute for looking.)
- [ ] `pytest` passes locally with `tshark` available.

If this adds or changes a **cause code**:
- [ ] Every `spec` / `clause` was verified by me against the 3GPP document — state document and version: …
- [ ] `plain` / `common_causes` are plain text (no markdown — they render straight into diagrams).

If this adds or changes an **adapter**:
- [ ] There is a test that cross-validates message count against `tshark` on a fixture.
- [ ] The fixture is self-generated or carries an explicit redistribution licence (a citation request is not a licence).
- [ ] Identity keys go through `telcoladder/identity.py`, and anything the adapter *releases* is declared in `Message.releases` (see `docs/plugin-contract.md`).

If this touches **`web/`**:
- [ ] `npm run build` was run and `telcoladder/static/` is updated.
- [ ] A new runtime dependency is listed in `NOTICE` (the test will tell you if not).
