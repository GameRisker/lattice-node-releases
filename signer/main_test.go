package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type zipEntry struct {
	name string
	data []byte
	mode os.FileMode
}

func archive(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, a := range entries {
		h := &zip.FileHeader{Name: a.name, Method: zip.Deflate}
		h.SetMode(a.mode)
		w, e := z.CreateHeader(h)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(a.data); e != nil {
			t.Fatal(e)
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func entries() []zipEntry {
	return []zipEntry{{nodeName, []byte("not executed node"), 0600}, {"t07-node-release-windows-amd64.exe", []byte("not executed verifier"), 0600}, {"install.ps1", []byte("throw 'not executed'"), 0600}}
}
func fixture(t *testing.T) (options, ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	pd, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		t.Fatal(e)
	}
	data := entries()
	data[2].data = installerFixture("v2026.11.13-deepseek-windows-selfuse1", digest(pd), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pd}))
	raw := archive(t, data)
	o := options{archive: filepath.Join(dir, "artifact.zip"), archiveHash: digest(raw), installerHash: digest(data[2].data), key: filepath.Join(dir, "key.pem"), fingerprint: digest(pd), tag: "v2026.11.13-deepseek-windows-selfuse1", source: strings.Repeat("a", 40), runID: "1234", out: filepath.Join(dir, "out")}
	if e = os.WriteFile(o.archive, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(o.key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	return o, pub
}
func TestPackageSignaturesAndInventory(t *testing.T) {
	o, pub := fixture(t)
	if e := packageRelease(o); e != nil {
		t.Fatal(e)
	}
	files, e := os.ReadDir(o.out)
	if e != nil {
		t.Fatal(e)
	}
	if len(files) != 9 {
		t.Fatalf("got %d files", len(files))
	}
	for _, n := range []string{"deepseek-manifest-windows.json", "release-index.json"} {
		b, _ := os.ReadFile(filepath.Join(o.out, n))
		s, _ := os.ReadFile(filepath.Join(o.out, n+".sig"))
		if !ed25519.Verify(pub, b, s) {
			t.Fatalf("invalid signature: %s", n)
		}
		b[0] ^= 1
		if ed25519.Verify(pub, b, s) {
			t.Fatal("modified bytes verified")
		}
	}
	b, _ := os.ReadFile(filepath.Join(o.out, "deepseek-manifest-windows.json"))
	var m manifest
	if e = json.Unmarshal(b, &m); e != nil {
		t.Fatal(e)
	}
	if m.SchemaVersion != 1 || m.SignatureType != "ed25519" || m.Channel != "selfuse" || m.Version != o.tag || len(m.Artifacts) != 1 || m.Artifacts[0].SHA256 != digest(entries()[0].data) {
		t.Fatal("manifest contract mismatch")
	}
	if b[len(b)-1] != '\n' {
		t.Fatal("missing canonical newline")
	}
	ib, _ := os.ReadFile(filepath.Join(o.out, "release-index.json"))
	var index releaseIndex
	if e = json.Unmarshal(ib, &index); e != nil {
		t.Fatal(e)
	}
	if index.SourceRunID != o.runID || index.ArchiveHash != o.archiveHash || index.KeyFingerprint != o.fingerprint || len(index.Files) != 6 {
		t.Fatal("index provenance mismatch")
	}
	if e = packageRelease(o); e == nil {
		t.Fatal("overwrote output")
	}
}
func TestRejectArchiveMembers(t *testing.T) {
	for _, bad := range []string{"../install.ps1", "/install.ps1", `sub\install.ps1`, "INSTALL.PS1", "extra.txt", nodeName} {
		t.Run(bad, func(t *testing.T) {
			a := entries()
			a[2].name = bad
			if _, e := unpack(archive(t, a)); e == nil {
				t.Fatal("unsafe member accepted")
			}
		})
	}
	a := entries()
	a[2].mode = os.ModeSymlink | 0777
	if _, e := unpack(archive(t, a)); e == nil {
		t.Fatal("symlink accepted")
	}
	a = entries()
	a[2].data = nil
	if _, e := unpack(archive(t, a)); e == nil {
		t.Fatal("empty file accepted")
	}
	a = entries()
	a[2].data = bytes.Repeat([]byte("a"), int(limits["install.ps1"])+1)
	if _, e := unpack(archive(t, a)); e == nil {
		t.Fatal("oversize accepted")
	}
	if _, e := unpack(archive(t, entries()[:2])); e == nil {
		t.Fatal("missing file accepted")
	}
	a = append(entries(), zipEntry{"extra", []byte("x"), 0600})
	if _, e := unpack(archive(t, a)); e == nil {
		t.Fatal("extra file accepted")
	}
}
func TestFailClosedInputs(t *testing.T) {
	tests := map[string]func(*options){"archive hash": func(o *options) { o.archiveHash = strings.Repeat("0", 64) }, "installer hash": func(o *options) { o.installerHash = strings.Repeat("0", 64) }, "fingerprint": func(o *options) { o.fingerprint = strings.Repeat("0", 64) }, "tag": func(o *options) { o.tag = "latest" }, "source": func(o *options) { o.source = "main" }, "run": func(o *options) { o.runID = "../123" }}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			o, _ := fixture(t)
			change(&o)
			if e := packageRelease(o); e == nil {
				t.Fatal("invalid input accepted")
			}
			if _, e := os.Stat(o.out); !os.IsNotExist(e) {
				t.Fatal("output created despite failure")
			}
		})
	}
}
func TestRejectKeyAndInputSymlinks(t *testing.T) {
	o, _ := fixture(t)
	os.Remove(o.key)
	os.Symlink(o.archive, o.key)
	if _, e := prepare(o); e == nil {
		t.Fatal("key symlink accepted")
	}
	o, _ = fixture(t)
	b, _ := os.ReadFile(o.key)
	os.WriteFile(o.key, append(b, b...), 0600)
	if _, e := prepare(o); e == nil {
		t.Fatal("multiple keys accepted")
	}
	o, _ = fixture(t)
	os.Symlink(filepath.Dir(o.out), o.out)
	if e := packageRelease(o); e == nil {
		t.Fatal("output symlink accepted")
	}
}

func TestVerifyDirectory(t *testing.T) {
	o, _ := fixture(t)
	if e := packageRelease(o); e != nil {
		t.Fatal(e)
	}
	if e := verifyDirectory(o.out, o); e != nil {
		t.Fatal(e)
	}
	bad := o
	bad.source = strings.Repeat("b", 40)
	if e := verifyDirectory(o.out, bad); e == nil {
		t.Fatal("wrong source accepted")
	}
	bad = o
	bad.tag = "v2026.11.14-deepseek-windows-selfuse2"
	if e := verifyDirectory(o.out, bad); e == nil {
		t.Fatal("wrong version accepted")
	}
	for _, n := range []string{nodeName, "install.ps1", "release-index.json.sig", "SHA256SUMS"} {
		p := filepath.Join(o.out, n)
		b, _ := os.ReadFile(p)
		os.WriteFile(p, append(b, 'x'), 0600)
		if e := verifyDirectory(o.out, o); e == nil {
			t.Fatalf("tampered %s accepted", n)
		}
		os.WriteFile(p, b, 0600)
	}
	os.WriteFile(filepath.Join(o.out, "secret.pem"), []byte("extra"), 0600)
	if e := verifyDirectory(o.out, o); e == nil {
		t.Fatal("extra file accepted")
	}
}

func installerFixture(tag, pin string, pub []byte) []byte {
	enc := base64.StdEncoding.EncodeToString
	return []byte("$release = Decode '" + enc([]byte("https://github.com/GameRisker/lattice-node-releases/releases/download/"+tag)) + "'\n$keyFingerprint = Decode '" + enc([]byte(pin)) + "'\n  [IO.File]::WriteAllBytes($key,[Convert]::FromBase64String('" + enc(pub) + "'))\n  if ((Get-FileHash -Algorithm SHA256 -LiteralPath $verify).Hash.ToLowerInvariant() -cne '" + digest(entries()[1].data) + "') { throw '安装校验工具指纹不符，未执行。' }\n")
}
func TestInstallerConstants(t *testing.T) {
	o, pub := fixture(t)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	pk := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	script := installerFixture(o.tag, o.fingerprint, pk)
	if e := installerConstants(script, o.tag, o.fingerprint, digest(entries()[1].data)); e != nil {
		t.Fatal(e)
	}
	if e := installerConstants([]byte(strings.ReplaceAll(string(script), "\n", "\r\n")), o.tag, o.fingerprint, digest(entries()[1].data)); e != nil {
		t.Fatal(e)
	}
	cases := map[string][]byte{"wrong release": installerFixture("v2026.11.14-deepseek-windows-selfuse2", o.fingerprint, pk), "wrong fingerprint": installerFixture(o.tag, strings.Repeat("0", 64), pk), "wrong key": installerFixture(o.tag, o.fingerprint, []byte("invalid")), "duplicate release": append(append([]byte{}, script...), []byte("$RELEASE = 'wrong'\n")...), "duplicate key": append(append([]byte{}, script...), script...), "malformed": []byte(strings.Replace(string(script), "$release = Decode '", "$release = Decode '!", 1)), "wrong verifier": []byte(strings.Replace(string(script), digest(entries()[1].data), strings.Repeat("0", 64), 1)), "missing": []byte("nothing")}
	for n, s := range cases {
		t.Run(n, func(t *testing.T) {
			if e := installerConstants(s, o.tag, o.fingerprint, digest(entries()[1].data)); e == nil {
				t.Fatal("invalid constants accepted")
			}
		})
	}
}
