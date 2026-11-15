package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Optional local-only integration with a separately authorized source checkout.
// CI in this public repository does not need or fetch private source code.
func TestActualSourceBootstrapOffline(t *testing.T) {
	sourceDir := os.Getenv("LATTICE_CODEX_SOURCE_TEST_DIR")
	if sourceDir == "" {
		t.Skip("explicit separate source checkout required")
	}
	sourceDir, err := filepath.Abs(sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	git := exec.Command("git", "rev-parse", "HEAD")
	git.Dir = sourceDir
	sourceRaw, err := git.Output()
	if err != nil {
		t.Fatal(err)
	}
	source := strings.TrimSpace(string(sourceRaw))
	const tag = "v2026.11.15-codex-unix-root2-1"
	root := t.TempDir()
	files := map[string][]byte{}
	run := func(dir string, env []string, args ...string) {
		t.Helper()
		cmd := exec.Command("go", args...)
		cmd.Dir = dir
		cmd.Env = append(append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0"), env...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("trusted-source tool failed: %v %s", err, out)
		}
	}
	for _, p := range platforms {
		parts := strings.Split(p, "-")
		env := []string{"GOOS=" + parts[0], "GOARCH=" + parts[1]}
		run(filepath.Join(sourceDir, "agents/codex-node-agent"), env, "build", "-buildvcs=false", "-ldflags", "-s -w -X lattice/codex-node-agent/internal/buildinfo.ReleaseNamespace=codex-unix-root2 -X lattice/codex-node-agent/internal/buildinfo.Version="+tag+" -X lattice/codex-node-agent/internal/buildinfo.Commit="+source, "-o", filepath.Join(root, "codex-node-agent-"+p), "./cmd/codex-node-agent")
		run(filepath.Join(sourceDir, "scripts/t07-node-release"), env, "build", "-trimpath", "-buildvcs=false", "-o", filepath.Join(root, "t07-node-release-"+p), ".")
		for _, program := range []string{"codex-node-agent", "t07-node-release"} {
			name := program + "-" + p
			files[name], _ = os.ReadFile(filepath.Join(root, name))
		}
	}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	privDER, _ := x509.MarshalPKCS8PrivateKey(key)
	pubDER, _ := x509.MarshalPKIXPublicKey(key.Public())
	pin := digest(pubDER)
	publicPath := filepath.Join(root, "fixture.pub.pem")
	privatePath := filepath.Join(root, "fixture.private.pem")
	os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0600)
	os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600)
	trust := map[string]any{"hubURL": "https://hub.gamerisker.com", "keys": []any{map[string]any{"keyId": "fixture-public-key", "publicJwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(make([]byte, 32))}}}}
	trustJSON, _ := json.Marshal(trust)
	trustPath := filepath.Join(root, "fixture-trust.json")
	os.WriteFile(trustPath, trustJSON, 0600)
	installerPath := filepath.Join(root, "install.sh")
	run(filepath.Join(sourceDir, "scripts/t07-node-release"), nil, "run", ".", "bootstrap", "--codex-channel", "root2", "--public-key", publicPath, "--release-url", "https://github.com/GameRisker/lattice-node-releases/releases/download/"+tag, "--hub-trust", trustPath, "--verifier-darwin", filepath.Join(root, "t07-node-release-darwin-arm64"), "--verifier-linux", filepath.Join(root, "t07-node-release-linux-amd64"), "--verifier-linux-arm64", filepath.Join(root, "t07-node-release-linux-arm64"), "--out", installerPath)
	files["install.sh"], _ = os.ReadFile(installerPath)
	raw := zipFixture(t, files, "")
	archivePath := filepath.Join(root, "unsigned.zip")
	os.WriteFile(archivePath, raw, 0600)
	o := options{archive: archivePath, archiveHash: digest(raw), installerHash: digest(files["install.sh"]), key: privatePath, fingerprint: pin, tag: tag, source: source, runID: "1234", out: filepath.Join(root, "signed")}
	if _, err := checkedPayload(o); err != nil {
		t.Fatalf("actual bootstrap check: %v", err)
	}
	if err := packageRelease(o); err != nil {
		t.Fatal(err)
	}
	if err := verifyDirectory(o.out, o); err != nil {
		t.Fatal(err)
	}
	t.Log("Actual source 3-platform binaries/verifiers + generated bootstrap checked/signed/verified offline; no payload execution or real key")
}
