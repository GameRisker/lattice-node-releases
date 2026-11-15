package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	_, err := verifyDirectorySnapshot(dir, o)
	return err
}

func verifyDirectorySnapshot(dir string, o options) (map[string][]byte, error) {
	if err := validateInputs(o); err != nil {
		return nil, err
	}
	info, e := os.Lstat(dir)
	if e != nil {
		return nil, e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("expected regular output directory")
	}
	inventory := map[string]uint64{}
	for n, l := range limits {
		inventory[n] = l
	}
	for _, n := range []string{"manifest-v2.json", "manifest-v2.json.sig", "release.pub.pem", "release-index.json", "release-index.json.sig", "SHA256SUMS"} {
		inventory[n] = 64 << 10
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return nil, e
	}
	if len(entries) != len(inventory) {
		return nil, errors.New("output inventory mismatch")
	}
	files := map[string][]byte{}
	for _, f := range entries {
		max, ok := inventory[f.Name()]
		if !ok {
			return nil, errors.New("unexpected output")
		}
		b, e := boundedFile(filepath.Join(dir, f.Name()), int64(max))
		if e != nil {
			return nil, e
		}
		files[f.Name()] = b
	}
	block, rest := pem.Decode(files["release.pub.pem"])
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 || digest(block.Bytes) != o.fingerprint {
		return nil, errors.New("public key pin mismatch")
	}
	parsed, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("wrong public key type")
	}
	for _, n := range []string{"manifest-v2.json", "release-index.json"} {
		signature, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(files[n+".sig"])))
		if err != nil || !ed25519.Verify(pub, files[n], signature) {
			return nil, errors.New("signature verification failed")
		}
	}
	var index releaseIndex
	if e = decodeStrict(files["release-index.json"], &index); e != nil {
		return nil, e
	}
	if index.SchemaVersion != 1 || index.Repository != "GameRisker/lattice" || index.Source != o.source || index.Tag != o.tag || index.SourceRunID != o.runID || index.ArchiveHash != o.archiveHash || index.KeyFingerprint != o.fingerprint {
		return nil, errors.New("signed provenance mismatch")
	}
	expected := []string{"manifest-v2.json", "manifest-v2.json.sig", "release.pub.pem"}
	for name := range limits {
		expected = append(expected, name)
	}
	sort.Strings(expected)
	if len(index.Files) != len(expected) {
		return nil, errors.New("signed inventory mismatch")
	}
	for i, n := range expected {
		r := index.Files[i]
		if r.File != n || r.Size != int64(len(files[n])) || r.SHA256 != digest(files[n]) {
			return nil, errors.New("signed output digest mismatch")
		}
	}
	if digest(files["install.sh"]) != o.installerHash {
		return nil, errors.New("installer digest mismatch")
	}
	if e := validatePayload(files, o); e != nil {
		return nil, e
	}
	var m manifest
	if e = decodeStrict(files["manifest-v2.json"], &m); e != nil {
		return nil, e
	}
	want := expectedManifest(files, o.tag)
	mb, _ := encoded(want)
	if !bytes.Equal(files["manifest-v2.json"], mb) {
		return nil, errors.New("release manifest mismatch")
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
		return nil, errors.New("checksums mismatch")
	}
	return files, nil
}
