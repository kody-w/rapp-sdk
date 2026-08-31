# Selected RAPP/1 authority fixture

This offline fixture selects owner-ratified RAPP/1 rev-14 from protected-main
PR #24 merge commit `caf6ef276cafa92aa744499af90dc1a28559941a`.

- `chain.jsonl.gz` contains the accepted 15-frame chain through rev-14.
- `SPEC.md.gz` contains the exact selected rev-14 normative bytes.
- `rev-13-SPEC.md.gz` retains the exact prior normative bytes for historical
  resolution through the rev-13 frame still present in the chain.
- `bootstrap.json` is the accepted content-addressed bootstrap profile.
- `manifest.json` pins every frame address and selected/historical hashes.

The manifest is language-neutral so Python and TypeScript implementations can
consume the same selected-authority values without translating hashes.

Gzip files use `mtime=0` and OS byte 255. The default suite verifies all raw
and compressed hashes before use. `tests/live_authority_refresh.py` separately
reproduces the fixture from immutable Git objects in a local authority
checkout.

The selected trust policy uses the bootstrap genesis, exact-integer number
profile, and persisted rev-14 head. A rev-13 prefix is therefore stale, while
the rev-13 frame remains resolvable inside the full accepted chain.
