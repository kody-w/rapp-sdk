# RAPP Projects SDK

`rapp_sdk.projects` is the typed integration surface for the public
[RAPP Projects](https://github.com/kody-w/rapp-projects) protocol.

```python
from rapp_sdk import (
    ProjectActor,
    build_project_frame,
    build_project_rappid,
    verify_project_stream,
)

stream_id = build_project_rappid("example", "handoff", b"stable entropy")
actor = ProjectActor(
    id="claude-code",
    runtime="claude-code",
    session_id="session-1",
    capabilities=("files", "tests"),
)

genesis = build_project_frame(
    "project.genesis",
    stream_id,
    0,
    "2026-08-31T00:00:00.000Z",
    {
        "project": "handoff",
        "title": "Cross-runtime handoff",
        "goal": "Resume without transcript archaeology",
        "owner": "example",
        "origin": "local",
        "visibility": "local",
    },
    None,
)
```

The SDK carries the twelve RAPP Projects events inside the already registered
RAPP/1 `body.pulse` frame kind, validates their required payload fields, verifies
complete local streams, and builds or
verifies, packs, reads, and addresses normative `rapp/1-egg` organism project
cells. Storage, locking, and Markdown projections remain application concerns
implemented by the `rapp-projects` reference application.

## RAPP Cell

Every project egg may be described as a **RAPP Cell**: it mutates only by
appending frames and can absorb verified lessons or capabilities from another
runtime through `cell.absorb`. This is vocabulary and behavior, not a new wire
type. The frame remains `rapp/1` and the package remains `.egg`.

Bounded autopilot uses `cell.policy` and `cell.cycle`. A policy declares
cadence, allowed and forbidden action classes, budgets, stop conditions, human
gates, and the next wakeup. Each cycle records observations, proposals,
applied/rejected mutations, receipts, and the next wakeup.
