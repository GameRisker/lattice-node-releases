# Codex Unix root2 release pipeline (not activated)

This is a separate trust/channel rollout, not a rotation signed by the old key.
Keep existing installers, manifests, packages, node identities and GitHub Latest
unchanged. Root2 artifacts have their own tag and Hub namespace. Never silently
migrate paired legacy nodes. This repository's DeepSeek workflow is unchanged.

## State and trust boundaries

The private source repository has a manual unsigned workflow. This public repo
has an independent, standard-library-only `codex-signer`, an exact source-artifact
reader, and a separately gated publisher. Downloaded executables/scripts are
**data only**, never run in a signing job. Go metadata checks detect misbuilt
packages; the reviewed source/workflow and cryptographic signatures supply trust.

No production key, environment configuration or live root2 release is established
by committing this code. Real Actions execution, real root2 installation, provider
login/model task, supervisor upgrade/reconnect and rollback remain NOT_RUN unless
separate dated evidence explicitly proves them. Local synthetic tests are not
those acceptance results. First publication requires explicit owner confirmation.

## Owner-approved setup, separate from code changes

In GameRisker/lattice-node-releases create `codex-unix-sign` and
`codex-unix-publish` environments, each with:
- required reviewer GameRisker (only owner);
- administrator bypass disabled;
- prevent-self-review **false**, so one owner account can trigger and review;
- custom deployment branch policy: only the branch `main`, no tag or wildcard.

The workflow reads these protections and fails closed if they drift. This does
not protect against the owner deliberately editing repository protections.
The assistant must not silently approve as the owner. Required approval before
signing covers public artifact staging as well as the later release decision.

Keep GITHUB_TOKEN default read-only, PR-approval permission disabled. Sign job uses
contents/actions read; only final publication gets contents write. No admin token.
Use only pinned Actions; any allowlist change needs separate explicit approval,
not an automated workaround. The new workflow uses hosted Go cache and refuses
missing toolchains, never relaxes repository policy to install setup-go.

Create or approve a dedicated artifact-reader GitHub App installed only on
GameRisker/lattice with Actions:read and mandatory Metadata:read. No repository
contents write, secrets, environment or administrative permission. Its short-lived
token downloads only the approved source artifact; it is not a signing authority.

In `codex-unix-sign` only:
- secret `CODEX_ROOT2_PRIVATE_KEY`: new Ed25519 PKCS8 PEM;
- secret `LATTICE_ARTIFACT_READER_APP_PRIVATE_KEY`: dedicated reader App key;
- variable `LATTICE_ARTIFACT_READER_APP_ID`.

No private key in the publish environment. Public release repo variable
`CODEX_ROOT2_PUBLIC_KEY_SHA256` is SPKI DER SHA256. Private source repo public
variables are `CODEX_ROOT2_PUBLIC_KEY_PEM`, `CODEX_ROOT2_PUBLIC_KEY_SHA256`, and
`CODEX_ROOT2_HUB_TRUST_JSON`. The PEM, Hub base64 raw key, and fingerprint must all
represent the exact same new key. The Hub trust descriptor must be independently
reviewed for the correct origin/lease keys; do not derive it from an untrusted
pairing response. Production Hub configuration is a later authorized deployment.

## Recovery before operational secret setup

GitHub environment secrets are write-only, not a backup. Do not generate the real
key until an owner-controlled recovery method is selected and tested. Plaintext
private keys must not be saved to workspace, chat, repository, output artifacts,
CLI arguments or logs. Signing uses `--key-env CODEX_ROOT2_PRIVATE_KEY`, reads it
into process memory, unsets the process environment variable, and clears mutable
key buffers on return. This is not a forensic guarantee about OS memory/swap.

The owner must choose either a known public encryption recipient with the private
recovery identity already held in an independent encrypted vault, or an audited
secure local passphrase-input/encryption/recovery workflow. Do not assume age,
iCloud Keychain syncing or a third-party vault already exists. A local Keychain
entry alone does not establish machine-loss recovery. Never export existing
Keychain items or the whole Keychain to manufacture a backup.

Only encrypted backup ciphertext/public metadata may persist in workspace; keep
an owner-controlled copy off that machine, with the decryption capability held
separately. Prove recovery by decrypting in memory and comparing only the derived
public fingerprint. Then store the operational secret through stdin, not a
secret-bearing argument. No real keys or recovery tools are created by this repo.

## Exact immutable handoff

1. Build reviewed current private main SHA using `codex-unix-build.yml`, first
   manual attempt only. It compiles three Unix nodes and three verifiers, then
   creates a fresh-install-only `install.sh`. Agents retain native Go linker
   settings (omit `-trimpath`) for channel/version/source checks; only secret-free
   hosted runner paths may enter published builds.
2. Review source SHA, successful run ID, exact artifact ID, archive SHA256,
   installer SHA256, new tag and pinned key fingerprint. Inspect the source and
   generated installer before approving its whole-file digest.
3. Dispatch this public repo workflow at the reviewed current public main SHA.
   Default `publish=false` signs/verifies only in the runner and uploads nothing.
   Both invocations are real signing operations and require the sign environment
   gate after key setup; do not call them a no-key dry run.
4. For an owner-approved publication, set `publish=true` and the exact binding:
   `publish:<release_tag>:<source_sha>:<artifact_sha256>`.
   This string binds the decision but does not itself prove human authorization;
   the owner confirmation and environment approvals remain mandatory.
5. The sign job checks environment policy, source/artifact provenance and archive
   bytes before injecting the signing secret. It rechecks immutable inputs while
   signing from a bounded in-memory snapshot. It independently verifies the
   resulting 13 files without a private-key environment before public staging.
6. The separate publish gate downloads the exact artifact ID from this run,
   verifies every signature, file hash, Go identity and installer binding, creates
   a new draft, checks remote asset hashes/sizes, and only then publishes. It never
   overwrites a tag, uses `--latest=false`, and never edits old channel assets.

A rerun is refused (`run_attempt` must be 1). After any ambiguous failure inspect
existing draft/tag/artifact state first; do not delete or overwrite it automatically.
If public main moves while awaiting approval, the gate refuses stale workflow code.
Do not bypass that gate: review a new first-attempt run instead.

## Artifacts and Hub handoff

13 files: install.sh; three codex-node-agent binaries; three t07-node-release
verifiers; manifest-v2.json and base64 signature; release.pub.pem;
release-index.json and base64 signature; SHA256SUMS. The signed index includes
source repository/SHA/run ID/archive digest/tag/public fingerprint and the exact
payload inventory. The signer checks its private key derives the pinned public key.

This workflow does not deploy the Hub. After installation/upgrade acceptance and
explicit deployment authorization, stage into a **new immutable root2 directory**,
verify it independently, and set the Hub's separate root2 directory and same public
key. Never merge root2 files into legacy release storage. Client SHA256/signature
checks remain required even with a held file descriptor; a descriptor is not a
protection against hostile in-place modification of an inode.

## Local verification

- `python3 -m unittest discover -s scripts -p 'test_*.py' -v`
- `(cd codex-signer && GOWORK=off GOPROXY=off GOSUMDB=off go test ./... -count=1)`
- `(cd signer && GOWORK=off go test ./... -count=1)` to check unchanged DeepSeek code.
- Parse workflow YAML; static contract checks are not actual hosted Actions runs.

Tests use synthetic keys and inert/compiled fixtures only. They do not read user
credentials, sign production packages, create accounts or contact real providers.

The publication verifier emits its exact 13-file digest/size inventory from the
same successfully verified in-memory snapshot. The publisher compares local
files and remote uploaded assets only against that inventory, never redefines
expected bytes from an altered directory. It still relies on the isolated trusted
runner and private inventory path; it is not a claim of immunity to a compromised
runner capable of replacing trusted code or the inventory itself.

Reference: GitHub's [environment management](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
and [deployment branch-policy API](https://docs.github.com/en/rest/deployments/branch-policies).
