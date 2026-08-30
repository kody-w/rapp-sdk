# RAPP SDK

> The RAPP SDK is the developer surface for building agents, twins, and integrations on the RAPP platform.

Write a `*_agent.py`, ship a `.twin/`, or embed the Brainstem — the SDK is the front door.

---

Part of the **RAPP** platform — the Rapid Agent Prototype Platform.
Explore the ecosystem: [Installer](https://github.com/kody-w/rapp-installer) ·
[Flight Deck](https://github.com/kody-w/rapp-flight-deck) ·
[Rings](https://github.com/kody-w/rapp-rings) ·
[Twin](https://github.com/kody-w/rapp-twin)

## Status

Early, and actively being built out. Interfaces will move.

## Protocol foundation

The first public package surface is a Python 3.11+, standard-library-only core
for strict RAPP/1 frames and append-only specification chains:

```python
from rapp_sdk import SpecChain, build_spec_revision_frame, verify_stream

chain = SpecChain.load("anchor/chain.jsonl")
selected = chain.resolve("head")
normative_bytes = chain.materialize(frame_hash=selected.frame_hash)
```

It provides strict I-JSON parsing, authority-compatible canonicalization,
domain-separated `H`/`Hb`, exact eleven-key frame construction and
verification, immutable historical specification resolution, and a
checksum-revalidating content-addressed cache. See
[`docs/spec-chain.md`](docs/spec-chain.md).

## License

Released under the MIT License.

<sub>RAPP, RAPP Brainstem, Twin in Residence, RAPP Flight Deck, and the RAPP family of
names are trademarks of the RAPP project. First published 2026-07-18 as part of the RAPP ecosystem.</sub>
