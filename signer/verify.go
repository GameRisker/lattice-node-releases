package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

func decodeStrict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
func verifyDirectory(dir string, o options) error {
	if !hashRE.MatchString(o.fingerprint) || !hashRE.MatchString(o.archiveHash) || !hashRE.MatchString(o.installerHash) || !shaRE.MatchString(o.source) || !tagRE.MatchString(o.tag) || o.runID == "" {
		return errors.New("expected provenance inputs required")
	}
	info, e := os.Lstat(dir)
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("expected regular output directory")
	}
	inventory := map[string]uint64{}
	for n, l := range limits {
		inventory[n] = l
	}
	for _, n := range []string{"deepseek-manifest-windows.json", "deepseek-manifest-windows.json.sig", "release.pub.pem", "release-index.json", "release-index.json.sig", "SHA256SUMS"} {
		inventory[n] = 64 << 10
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	if len(entries) != len(inventory) {
		return errors.New("output inventory mismatch")
	}
	files := map[string][]byte{}
	for _, f := range entries {
		max, ok := inventory[f.Name()]
		if !ok {
			return errors.New("unexpected output")
		}
		b, e := boundedFile(filepath.Join(dir, f.Name()), int64(max))
		if e != nil {
			return e
		}
		files[f.Name()] = b
	}
	block, rest := pem.Decode(files["release.pub.pem"])
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 || digest(block.Bytes) != o.fingerprint {
		return errors.New("public key pin mismatch")
	}
	parsed, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return e
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return errors.New("wrong public key type")
	}
	for _, n := range []string{"deepseek-manifest-windows.json", "release-index.json"} {
		if !ed25519.Verify(pub, files[n], files[n+".sig"]) {
			return errors.New("signature verification failed")
		}
	}
	var index releaseIndex
	if e = decodeStrict(files["release-index.json"], &index); e != nil {
		return e
	}
	if index.SchemaVersion != 1 || index.Repository != "GameRisker/lattice" || index.Source != o.source || index.Tag != o.tag || index.SourceRunID != o.runID || index.ArchiveHash != o.archiveHash || index.KeyFingerprint != o.fingerprint {
		return errors.New("signed provenance mismatch")
	}
	expected := []string{nodeName, "t07-node-release-windows-amd64.exe", "install.ps1", "deepseek-manifest-windows.json", "deepseek-manifest-windows.json.sig", "release.pub.pem"}
	sort.Strings(expected)
	if len(index.Files) != len(expected) {
		return errors.New("signed inventory mismatch")
	}
	for i, n := range expected {
		r := index.Files[i]
		if r.File != n || r.Size != int64(len(files[n])) || r.SHA256 != digest(files[n]) {
			return errors.New("signed output digest mismatch")
		}
	}
	if digest(files["install.ps1"]) != o.installerHash {
		return errors.New("installer digest mismatch")
	}
	if e := installerConstants(files["install.ps1"], o.tag, o.fingerprint, digest(files["t07-node-release-windows-amd64.exe"])); e != nil {
		return e
	}
	var m manifest
	if e = decodeStrict(files["deepseek-manifest-windows.json"], &m); e != nil {
		return e
	}
	want := manifest{1, "ed25519", "selfuse", o.tag, []artifact{{"windows-amd64", nodeName, int64(len(files[nodeName])), digest(files[nodeName])}}}
	mb, _ := encoded(want)
	if !bytes.Equal(files["deepseek-manifest-windows.json"], mb) {
		return errors.New("release manifest mismatch")
	}
	names := make([]string, 0, len(files)-1)
	for n := range files {
		if n != "SHA256SUMS" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var sums bytes.Buffer
	for _, n := range names {
		fmt.Fprintf(&sums, "%s  %s\n", digest(files[n]), n)
	}
	if !bytes.Equal(files["SHA256SUMS"], sums.Bytes()) {
		return errors.New("checksums mismatch")
	}
	return nil
}
