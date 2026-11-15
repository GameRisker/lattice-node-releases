# Codex Unix root2 isolated signer

This independent Go-standard-library-only tool treats all downloaded content as
DATA. It never runs an installer, verifier or node from the source artifact.
No production key is included. Tests compile inert Go fixtures for three
platforms and use a publicly known deterministic test key only.

## Interface

Common reviewed bindings:
`--archive-sha256`, `--installer-sha256`, `--public-key-sha256` (SPKI DER SHA256),
`--tag vYYYY.MM.DD-codex-unix-root2-N`, `--source-sha` (40 hex),
`--source-run-id` (positive decimal).

- `--check-archive --archive PATH`: validate inert input without a key or output.
- `--archive PATH --key-env CODEX_ROOT2_PRIVATE_KEY --out NEWDIR`: sign after
  revalidation, using only the scoped environment secret. The variable is removed
  from the process environment after access. No plaintext key file is written.
- `--key PATH` is an alternative mutually exclusive key input for isolated local
  tests or an explicitly approved mechanism. The Actions workflow should not use
  it. Private key buffers are cleared best-effort; this is not a promise of OS or
  garbage-collector memory erasure.
- `--verify-dir DIR`: independently verify all signed outputs without a key.
  The CLI rejects private-key options for verification/preflight modes.

Input: `install.sh`, `codex-node-agent-{darwin-arm64,linux-amd64,linux-arm64}`,
`t07-node-release-{darwin-arm64,linux-amd64,linux-arm64}`. Exactly seven regular
files, no paths, symlinks, duplicates or encrypted members. The bounded ZIP policy
rejects ZIP64/split archives and central directories larger than 64 KiB; the
approved archive and expanded payload are each bounded to 512 MiB.

Output: those seven files plus `manifest-v2.json`, `manifest-v2.json.sig`,
`release.pub.pem`, `release-index.json`, `release-index.json.sig`, `SHA256SUMS`.
Both detached signatures are base64 text. The manifest uses schema 1 and
`channel=codex-unix-root2`; the public Hub route requires exactly this format.
The signed release index binds source repo/SHA/run, tag, input archive hash,
public root and every payload/manifest/public-key file digest. Verification
requires all thirteen regular files and regenerates canonical manifest/checksums.

Before touching the key, the signer checks the archive hash, exact inventory,
all six programs' Go module/platform metadata, and all three node programs'
explicit linker namespace/version/Commit against reviewed inputs. Root2 nodes
must omit `-trimpath` to retain linker metadata; verifiers may use it.
The installer whole-file SHA256 remains mandatory. Additional constant assertions
bind the root2 namespace, expected Hub origin, pinned public key and three verifier
hashes. These assertions are drift guards, not a shell sandbox or a proof that
arbitrary reviewed code is safe.

The caller must independently authenticate GitHub run/artifact provenance and
use a private immutable archive snapshot. This tool hashes and reads the archive
into a bounded in-memory snapshot before signing; output creation is exclusive
and refuses an existing directory. Publication must re-run `--verify-dir` and
must never overwrite an existing Release/tag or silently change a legacy channel.

Not covered: actual GitHub gates, signing-key custody, native node install,
login, supervisor upgrade/rollback, model tasks or production publication.

The production installer constant guard intentionally binds
`trusted_hub=https://hub.gamerisker.com`. This does not authorize executing it
against production for tests. A separate QA-origin installation needs a separately
reviewed test trust channel, not silent edits to a signed production installer.

Validation performed locally: standard synthetic sign/verify/refusal tests,
`go vet`, and an opt-in offline integration with the actual source checkout.
That integration builds all three actual agents and verifiers and generates the
actual bootstrap through the trusted source tool, then check/sign/verifies with
the deterministic test key. None of those packaged binaries/installers is run.
To reproduce only with an explicitly authorized source checkout:
`LATTICE_CODEX_SOURCE_TEST_DIR=/absolute/source GOWORK=off go test -run TestActualSourceBootstrapOffline -v`.

For publication, use `--verify-dir DIR --verified-inventory-out NEWFILE` with the
common reviewed bindings. The JSON object contains all thirteen file names and
`{size, sha256}` records calculated from the exact verified in-memory snapshot.
The output is exclusively created with mode 0600, cannot overwrite anything, and
must be outside the signed directory (including symlink aliases). The publisher
must compare its uploaded bytes to this inventory, not derive a new expected
inventory by re-reading potentially changed signed paths. Verification mode still
forbids private-key options and the `CODEX_ROOT2_PRIVATE_KEY` environment variable.
