# Maintained DeepSeek Windows self-use release pipeline

This repository contains only the necessary release control code. Application source stays private. This channel does not replace the production release trust root or Hub authorization keys. Installing the first bootstrap still requires a trusted distribution source and review of its published checksum; a signature on the binary does not authenticate an arbitrary downloaded PowerShell script by itself.

## One-time setup (separate owner authorization required)

Do not add secrets until native approval gates have been configured and verified.

1. Create `deepseek-windows-sign` and `deepseek-windows-publish` environments **in this public repository**. Select deployment branch `main` (branch, not tag), reviewer `GameRisker`, allow self-review for owner-triggered runs, disallow administrator bypass. Review approval behavior in a non-secret smoke test. These controls are not installed by committing this workflow. GitHub Pro/Team private repositories lack this native reviewer feature.
2. Create a private GitHub App, install it **only on `GameRisker/lattice`**, with Actions read and automatic Metadata read. No Contents write, administration, workflow write, webhooks, or user OAuth token is needed. Actions read includes the repository's workflow runs, logs and artifacts, not only this package. `actions/create-github-app-token` further scopes each token to this repository and Actions read; token revocation at job end remains enabled.
3. Store the App ID as signing-environment variable `LATTICE_ARTIFACT_READER_APP_ID`; store the App PEM only as signing-environment secret `LATTICE_ARTIFACT_READER_APP_PRIVATE_KEY`.
4. Provision a dedicated persisted Ed25519 PKCS8 PEM signing key, never a production key. Store it only in signing-environment secret `DEEPSEEK_WINDOWS_SELFUSE_PRIVATE_KEY`. Keep an encrypted backup in an owner-approved password manager/offline location; Actions secrets are not a recoverable backup. Do not paste private keys into issues, logs, workflow inputs or artifacts.
5. Set **repository variable** `DEEPSEEK_WINDOWS_SELFUSE_PUBLIC_KEY_SHA256` to SHA256 of the DER-encoded PKIX public key. Configure the same fingerprint and PUBLIC PEM in the private build repository (`DEEPSEEK_WINDOWS_SELFUSE_PUBLIC_KEY_PEM`). Public values are not secrets. Do not put either private key in the publish environment or ordinary repository secrets.
6. Review account Actions allowance and spending controls before private Windows builds. Public standard hosted compute is free under current GitHub policy; private compute and artifact retention can consume allowance or incur charges. No paid settings are changed by this code.

## Repeatable release

1. Review and commit private `main`. Run `.github/workflows/deepseek-windows-build.yml` on that exact SHA, providing a new `vYYYY.MM.DD-deepseek-windows-selfuseN` tag. It produces three inert distributable files without a persistent private key.
2. Inspect the completed first-attempt run, tests and generated installer. Record run ID, artifact ID, archive SHA256, installer SHA256, source SHA and intended tag from its summary. Artifacts expire after seven days; rebuild if expired. Do not silently select a newer artifact by name.
3. Run `.github/workflows/deepseek-windows-release.yml` here on its exact reviewed main SHA. Supply those immutable values; leave `publish=false` for signing-only rehearsal, which does not upload the generated package and discards it with the runner. Signing still requires a separate approved key use. No signing-only run grants future publishing permission.
4. Approve the `deepseek-windows-sign` deployment after reviewing the inputs and trusted public scripts. Downloaded bytes are never executed in this job. **When `publish=true`, this first approval also authorizes publicly downloadable artifact staging in this public repository; the second gate does not keep those binaries private.** A successful package contains signed provenance and an integrity-checked installer, verifier, and node binary.
5. When publication was explicitly requested for this version, the distinct `deepseek-windows-publish` job awaits owner approval. It receives no App/signing secret. It verifies both signatures, pinned public key, all files and exact source/run/tag/approved archive and installer digests before creating a **new draft** whose tag targets the reviewed public workflow SHA. Remote names, counts, lengths and SHA256 digests must match before the draft is published. It never overwrites an existing tag or release.
6. Review the release and download hashes. Windows full installer/Harness download, pairing, startup and actual model inference remain **NOT_RUN** by this workflow. Signature and parser checks are not end-to-end acceptance. Production web URL remains unchanged; wiring a production entry requires separate acceptance and authorization.

A rerun is rejected: use a new dispatch with reviewed immutable inputs. On failure after draft creation, inspect the draft and tag before taking further action. Do not delete or overwrite blindly; use a new version unless the owner separately approves recovery. Signed package retention is seven days; published releases are the durable distribution record.

## Security and maintenance

- Inputs bind both private source and public workflow commits. App token lifetime is short, but its private key is a long-lived credential and must be protected. Only the sign job has it. Pin actions by full commit SHA and review updates.
- Artifacts are untrusted data even if checksums match. The minimal standard-library Go signer enforces ZIP allowlists/limits, never executes packaged scripts or executables, signs a generated manifest and a provenance/file index. The publish job independently verifies that index before upload. A compromised approved source build can still produce malicious installer code: review source/build workflow and installer digest, not just green CI.
- Public logs/indices expose source SHA, run ID, and approved release hashes. They do not copy private build logs, arbitrary artifacts, application source, or account data.
- Rotate App keys by adding a new key, updating the environment secret, verifying scoped reads, then revoking the old key. App keys do not expire automatically. Do not rotate the Ed25519 release key per run. Record public key IDs and preserve old release verification; a new installer pin requires a separately approved trust migration. Never assume old installed clients trust a new key.
- Test recovery from encrypted backup without printing key material. On compromise stop releases, revoke App key/access as applicable, assess affected signed versions, and explicitly distribute a replacement trust root. Previously downloaded installers cannot be silently revoked.
- Review runner/toolchain support, pinned action updates, allowance, and expiry of build artifacts as routine maintenance. No scheduler or automatic maintenance publication is enabled.

## Local isolated checks

`python -m unittest discover -s scripts -p 'test_*.py' -v`

`cd signer && GOTOOLCHAIN=local go test ./...`

Tests use synthetic data and throwaway signing keys only. They do not contact GitHub, use real credentials, call models, or install on a user machine.
