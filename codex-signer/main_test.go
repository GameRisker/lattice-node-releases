package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func compileFixtures(t *testing.T, tag, source string) map[string][]byte {
	t.Helper()
	root := t.TempDir()
	files := map[string][]byte{}
	for _, kind := range []string{"node", "verifier"} {
		dir := filepath.Join(root, kind)
		os.MkdirAll(dir, 0700)
		module := "lattice/t07-node-release"
		target := "."
		contents := map[string]string{"main.go": "package main\nfunc main(){panic(\"must never execute fixture\")}\n"}
		if kind == "node" {
			module = "lattice/codex-node-agent"
			target = "./cmd/codex-node-agent"
			contents = map[string]string{
				"internal/buildinfo/info.go":   "package buildinfo\nvar Version=\"dev\"\nvar ReleaseNamespace=\"legacy\"\nvar Commit=\"\"\n",
				"cmd/codex-node-agent/main.go": "package main\nimport(\"fmt\";\"lattice/codex-node-agent/internal/buildinfo\")\nfunc main(){fmt.Println(buildinfo.Version,buildinfo.ReleaseNamespace,buildinfo.Commit);panic(\"must never execute fixture\")}\n",
			}
		}
		contents["go.mod"] = "module " + module + "\n\ngo 1.25.0\n"
		for name, content := range contents {
			p := filepath.Join(dir, name)
			os.MkdirAll(filepath.Dir(p), 0700)
			os.WriteFile(p, []byte(content), 0600)
		}
		for _, p := range platforms {
			parts := strings.Split(p, "-")
			out := filepath.Join(root, kind+"-"+p)
			args := []string{"build", "-buildvcs=false", "-o", out}
			if kind == "node" {
				args = append(args, "-ldflags", "-s -w -X lattice/codex-node-agent/internal/buildinfo.ReleaseNamespace=codex-unix-root2 -X lattice/codex-node-agent/internal/buildinfo.Version="+tag+" -X lattice/codex-node-agent/internal/buildinfo.Commit="+source)
			} else {
				args = append(args, "-trimpath")
			}
			args = append(args, target)
			cmd := exec.Command("go", args...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0", "GOOS="+parts[0], "GOARCH="+parts[1])
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("fixture compile %v %s", err, output)
			}
			prefix := "t07-node-release-"
			if kind == "node" {
				prefix = "codex-node-agent-"
			}
			files[prefix+p], _ = os.ReadFile(out)
		}
	}
	return files
}
func installerFixture(files map[string][]byte, o options, pub []byte) []byte {
	return []byte(fmt.Sprintf(`#!/usr/bin/env bash
release_url='https://github.com/GameRisker/lattice-node-releases/releases/download/%s'
key_fingerprint='%s'
codex_channel='root2'
trusted_hub='https://hub.gamerisker.com'
  Darwin/arm64) platform=darwin-arm64; verifier_hash='%s' ;;
  Linux/x86_64|Linux/amd64) platform=linux-amd64; verifier_hash='%s' ;;
  Linux/aarch64|Linux/arm64) platform=linux-arm64; verifier_hash='%s' ;;
  download_program=codex-unix-root2
--manifest-url "${hub%%/}/downloads/${download_program}/manifest-v2.json"
[[ "$(hash_file "$work/verifier")" = "$verifier_hash" ]] || fail 'fixture'
  (( ! reinstall )) || fail 'fixture'
  [[ ! -e "$config_dir/agent.json" && ! -L "$config_dir/agent.json" ]] || fail 'fixture'
cat > "$work/release.pub.pem" <<'LATTICE_PUBLIC_KEY'
%sLATTICE_PUBLIC_KEY
`, o.tag, o.fingerprint, digest(files["t07-node-release-darwin-arm64"]), digest(files["t07-node-release-linux-amd64"]), digest(files["t07-node-release-linux-arm64"]), pub))
}
func zipFixture(t *testing.T, files map[string][]byte, change string) []byte {
	t.Helper()
	var raw bytes.Buffer
	z := zip.NewWriter(&raw)
	for n, b := range files {
		h := &zip.FileHeader{Name: n, Method: zip.Deflate}
		h.SetMode(0600)
		if change == "symlink" && n == "install.sh" {
			h.SetMode(os.ModeSymlink | 0700)
		}
		w, err := z.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(b)
	}
	if change == "extra" || change == "duplicate" {
		name := "../escape"
		if change == "duplicate" {
			name = "install.sh"
		}
		w, _ := z.Create(name)
		w.Write([]byte("x"))
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}
func TestSignVerifyAndRefuse(t *testing.T) {
	const tag = "v2026.11.15-codex-unix-root2-1"
	source := strings.Repeat("a", 40)
	files := compileFixtures(t, tag, source)
	// Deterministic public test seed only. It must never be used for a release.
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pubDER, _ := x509.MarshalPKIXPublicKey(key.Public())
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	dir := t.TempDir()
	o := options{tag: tag, source: source, runID: "1234", fingerprint: digest(pubDER), key: filepath.Join(dir, "test-key.pem"), archive: filepath.Join(dir, "unsigned.zip"), out: filepath.Join(dir, "signed")}
	os.WriteFile(o.key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600)
	files["install.sh"] = installerFixture(files, o, pub)
	o.installerHash = digest(files["install.sh"])
	raw := zipFixture(t, files, "")
	o.archiveHash = digest(raw)
	os.WriteFile(o.archive, raw, 0600)
	if err := packageRelease(o); err != nil {
		t.Fatal(err)
	}
	if err := verifyDirectory(o.out, o); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(o.out)
	if len(entries) != 13 {
		t.Fatalf("inventory %d", len(entries))
	}
	if err := packageRelease(o); err == nil {
		t.Fatal("existing output overwritten")
	}

	t.Run("verified-inventory-snapshot", func(t *testing.T) {
		snapshot, err := verifyDirectorySnapshot(o.out, o)
		if err != nil {
			t.Fatal(err)
		}
		original := append([]byte{}, snapshot["install.sh"]...)
		installed := filepath.Join(o.out, "install.sh")
		os.WriteFile(installed, []byte("changed after verification"), 0600)
		defer os.WriteFile(installed, original, 0600)
		output := filepath.Join(t.TempDir(), "inventory.json")
		if err := writeVerifiedInventory(o.out, output, snapshot); err != nil {
			t.Fatal(err)
		}
		body, _ := os.ReadFile(output)
		var inventory map[string]verifiedRecord
		if err := json.Unmarshal(body, &inventory); err != nil {
			t.Fatal(err)
		}
		if len(inventory) != 13 || inventory["install.sh"].SHA256 != digest(original) || inventory["install.sh"].Size != int64(len(original)) || inventory["SHA256SUMS"].SHA256 != digest(snapshot["SHA256SUMS"]) {
			t.Fatal("inventory was not the verified snapshot")
		}
		if err := writeVerifiedInventory(o.out, output, snapshot); err == nil {
			t.Fatal("inventory overwritten")
		}
		if err := writeVerifiedInventory(o.out, filepath.Join(o.out, "inventory.json"), snapshot); err == nil {
			t.Fatal("inventory written inside signed directory")
		}
		link := filepath.Join(t.TempDir(), "alias")
		if err := os.Symlink(o.out, link); err != nil {
			t.Fatal(err)
		}
		if err := writeVerifiedInventory(o.out, filepath.Join(link, "inventory.json"), snapshot); err == nil {
			t.Fatal("symlink alias bypassed inventory boundary")
		}
	})
	t.Run("private-key-environment", func(t *testing.T) {
		candidate := o
		candidate.key = ""
		candidate.keyEnv = "CODEX_ROOT2_PRIVATE_KEY"
		t.Setenv(candidate.keyEnv, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
		if _, err := prepare(candidate); err != nil {
			t.Fatal(err)
		}
		if _, exists := os.LookupEnv(candidate.keyEnv); exists {
			t.Fatal("key environment was not removed")
		}
		candidate.key = o.key
		if _, err := prepare(candidate); err == nil {
			t.Fatal("mutually exclusive inputs accepted")
		}
	})
	t.Run("no-key-preflight", func(t *testing.T) {
		candidate := o
		candidate.key = "/does/not/exist"
		if _, err := checkedPayload(candidate); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unsigned-tampering", func(t *testing.T) {
		for _, kind := range []string{"extra", "duplicate", "symlink", "wrong-digest", "wrong-source", "wrong-installer", "invalid-date", "wrong-verifier-platform", "script-node", "giant-directory"} {
			t.Run(kind, func(t *testing.T) {
				copyFiles := map[string][]byte{}
				for n, b := range files {
					copyFiles[n] = b
				}
				candidate := o
				candidate.key = "/nonexistent/private-key"
				switch kind {
				case "wrong-source":
					candidate.source = strings.Repeat("b", 40)
				case "wrong-installer":
					candidate.installerHash = strings.Repeat("0", 64)
				case "invalid-date":
					candidate.tag = "v2026.99.99-codex-unix-root2-1"
				case "wrong-verifier-platform":
					copyFiles["t07-node-release-linux-amd64"] = copyFiles["t07-node-release-darwin-arm64"]
				case "script-node":
					copyFiles["codex-node-agent-linux-amd64"] = []byte("#!/bin/sh\nexit 0\n")
				}
				archive := zipFixture(t, copyFiles, kind)
				if kind == "giant-directory" {
					archive[len(archive)-12] = 255
					archive[len(archive)-11] = 255
				}
				candidate.archive = filepath.Join(t.TempDir(), "input.zip")
				os.WriteFile(candidate.archive, archive, 0600)
				candidate.archiveHash = digest(archive)
				if kind == "wrong-digest" {
					candidate.archiveHash = strings.Repeat("0", 64)
				}
				_, err := prepare(candidate)
				if err == nil {
					t.Fatal("bad archive accepted")
				}
				if strings.Contains(err.Error(), "private-key") {
					t.Fatalf("key read before rejection: %v", err)
				}
			})
		}
	})

	t.Run("installer-drift", func(t *testing.T) {
		for _, change := range []struct{ from, to string }{
			{"codex_channel='root2'", "codex_channel='legacy'"},
			{"trusted_hub='https://hub.gamerisker.com'", "trusted_hub='https://attacker.invalid'"},
			{"download_program=codex-unix-root2", "download_program=codex-node-agent"},
			{digest(files["t07-node-release-linux-amd64"]), strings.Repeat("0", 64)},
			{"  (( ! reinstall )) || fail", "  true || fail"},
		} {
			copyFiles := map[string][]byte{}
			for n, b := range files {
				copyFiles[n] = b
			}
			copyFiles["install.sh"] = []byte(strings.Replace(string(files["install.sh"]), change.from, change.to, 1))
			candidate := o
			candidate.installerHash = digest(copyFiles["install.sh"])
			if err := installerConstants(copyFiles, candidate); err == nil {
				t.Fatalf("installer drift accepted: %s", change.from)
			}
		}
	})
	t.Run("signed-tampering", func(t *testing.T) {
		for _, name := range []string{"manifest-v2.json", "manifest-v2.json.sig", "release-index.json", "release-index.json.sig", "release.pub.pem", "SHA256SUMS", "codex-node-agent-linux-amd64", "install.sh"} {
			t.Run(name, func(t *testing.T) {
				p := filepath.Join(o.out, name)
				original, _ := os.ReadFile(p)
				os.WriteFile(p, append(append([]byte{}, original...), byte('x')), 0600)
				defer os.WriteFile(p, original, 0600)
				if err := verifyDirectory(o.out, o); err == nil {
					t.Fatal("tampered release accepted")
				}
			})
		}
	})

	t.Run("wrong-signing-key", func(t *testing.T) {
		other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
		otherDER, _ := x509.MarshalPKCS8PrivateKey(other)
		candidate := o
		candidate.key = filepath.Join(t.TempDir(), "wrong.pem")
		os.WriteFile(candidate.key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER}), 0600)
		if _, err := prepare(candidate); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
			t.Fatalf("wrong key not refused: %v", err)
		}
	})
	t.Run("signed-extra-file", func(t *testing.T) {
		p := filepath.Join(o.out, "unexpected")
		os.WriteFile(p, []byte("x"), 0600)
		defer os.Remove(p)
		if verifyDirectory(o.out, o) == nil {
			t.Fatal("extra signed file accepted")
		}
	})
	t.Run("provenance-mismatch", func(t *testing.T) {
		candidate := o
		candidate.runID = "1235"
		if verifyDirectory(o.out, candidate) == nil {
			t.Fatal("wrong run accepted")
		}
	})
}
