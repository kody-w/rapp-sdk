# Pinned RAPP/1 authority fixture

This offline fixture is copied exactly from `kody-w/rapp-1` commit
`bfa0706a4dd448b98b59c68aece0761d625923cb`.

- `chain.jsonl.gz` is portable deterministic gzip (`mtime=0`, OS byte 255) of
  `anchor/chain.jsonl`.
- `SPEC.md.gz` is portable deterministic gzip (`mtime=0`, OS byte 255) of
  `SPEC.md`.
- `manifest.json` records the source commit, raw and compressed checksums,
  byte counts, and all 14 frame addresses.

The default test suite hard-codes and verifies the fixture checksums before
decompression. `tests/live_authority_refresh.py` is the separate optional
utility that reproduces these bytes with `git show` from a local authority
checkout.
