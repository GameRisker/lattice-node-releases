# Root2 code-only pipeline evidence — 2026-11-15

Scope: new independent public signer/verifier, artifact reader, guarded publisher,
manual release workflow and a synthetic-only push CI. Existing DeepSeek signer,
reader, publisher and workflow remain unchanged. No real environment/security
setting, App, credential, operational key, artifact release or Hub deployment was
created by this code work.

Local verification:
- Python scripts: 43 synthetic tests PASS (source lineage, redirect/token hygiene,
  environment gates, publication binding, inventory/draft/remote digest handling,
  no overwrite/latest changes, workflow secret boundaries).
- Independent Codex Go signer suite PASS, go vet PASS; race PASS 50.763s.
- Existing DeepSeek signer regression PASS 0.533s.
- Real private source's three-platform agents and verifiers plus its actual
  bootstrap generator were exercised offline with a known synthetic test seed:
  check archive → sign → verify PASS (initial 14.379s; independent reviewer 7.909s;
  coordinator rerun 5.108s). No downloaded payload was executed and no production
  key, Hub, model or pairing endpoint was used.
- Final independent audit accepted the same-snapshot inventory handoff: expected
  hashes cannot be redefined merely by changing package files after verification.
  Local/remote publication comparisons remain pinned to the verifier's snapshot.
- All workflow YAML parsed successfully. This is not hosted Actions execution.

The only automatic workflow added is synthetic CI with contents:read, no
protected environment and no secret references. Actual signing/publication is
workflow_dispatch-only; publication defaults false, requires exact owner binding
and two protected environment gates. The new Go signer reads a real signing key
only if deliberately invoked with a key argument in a later authorized run.

Outstanding: actual unsigned source Actions with configured public trust; real
key recovery/custody and environment setup; actual reviewed signing/publication;
real initial installation, task execution, supervisor upgrade/reconnect/rollback.
A local signature fixture or successful synthetic CI does not satisfy these.
