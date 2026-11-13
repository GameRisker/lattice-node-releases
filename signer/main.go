// A minimal release packager. Artifact bytes are data, never executed.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

const nodeName = "deepseek-node-agent-windows-amd64.exe"

var limits = map[string]uint64{nodeName: 256 << 20, "t07-node-release-windows-amd64.exe": 64 << 20, "install.ps1": 2 << 20}
var hashRE = regexp.MustCompile(`^[a-f0-9]{64}$`)
var shaRE = regexp.MustCompile(`^[a-f0-9]{40}$`)
var tagRE = regexp.MustCompile(`^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}-deepseek-windows-selfuse[0-9]+$`)

type options struct{ archive, archiveHash, installerHash, key, fingerprint, tag, source, runID, out string }
type artifact struct {
	Platform string `json:"platform"`
	File     string `json:"file"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}
type manifest struct {
	SchemaVersion int        `json:"schemaVersion"`
	SignatureType string     `json:"signatureType"`
	Channel       string     `json:"channel"`
	Version       string     `json:"version"`
	Artifacts     []artifact `json:"artifacts"`
}
type fileRecord struct {
	File   string `json:"file"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type releaseIndex struct {
	SourceRunID    string       `json:"sourceRunID"`
	SchemaVersion  int          `json:"schemaVersion"`
	Repository     string       `json:"sourceRepository"`
	Source         string       `json:"sourceSHA"`
	Tag            string       `json:"tag"`
	ArchiveHash    string       `json:"archiveSHA256"`
	KeyFingerprint string       `json:"publicKeySHA256"`
	Files          []fileRecord `json:"files"`
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func encoded(v any) ([]byte, error) {
	b, e := json.MarshalIndent(v, "", "  ")
	return append(b, '\n'), e
}
func boundedFile(path string, maximum int64) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("invalid input file type or size")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maximum+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > maximum {
		return nil, errors.New("input too large")
	}
	return b, nil
}
func unpack(raw []byte) (map[string][]byte, error) {
	z, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		return nil, e
	}
	if len(z.File) != len(limits) {
		return nil, errors.New("archive must contain exact allowlist")
	}
	out := map[string][]byte{}
	for _, f := range z.File {
		max, ok := limits[f.Name]
		if !ok || out[f.Name] != nil || !f.Mode().IsRegular() || f.UncompressedSize64 == 0 || f.UncompressedSize64 > max {
			return nil, errors.New("invalid, duplicate, non-regular or oversized archive member")
		}
		r, e := f.Open()
		if e != nil {
			return nil, e
		}
		b, e := io.ReadAll(io.LimitReader(r, int64(max)+1))
		ce := r.Close()
		if e != nil {
			return nil, e
		}
		if ce != nil {
			return nil, ce
		}
		if uint64(len(b)) != f.UncompressedSize64 {
			return nil, errors.New("archive member length mismatch")
		}
		out[f.Name] = b
	}
	return out, nil
}
func signingKey(raw []byte, pin string) (ed25519.PrivateKey, []byte, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("expected one PKCS8 PEM private key")
	}
	parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, nil, errors.New("invalid PKCS8 key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, errors.New("key must be Ed25519")
	}
	der, e := x509.MarshalPKIXPublicKey(key.Public())
	if e != nil {
		return nil, nil, e
	}
	if digest(der) != pin {
		return nil, nil, errors.New("public key fingerprint mismatch")
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
func prepare(o options) (map[string][]byte, error) {
	if !hashRE.MatchString(o.archiveHash) || !hashRE.MatchString(o.installerHash) || !hashRE.MatchString(o.fingerprint) || !shaRE.MatchString(o.source) || !tagRE.MatchString(o.tag) || !regexp.MustCompile(`^[1-9][0-9]{0,19}$`).MatchString(o.runID) {
		return nil, errors.New("invalid immutable release inputs")
	}
	raw, e := boundedFile(o.archive, 350<<20)
	if e != nil {
		return nil, e
	}
	if digest(raw) != o.archiveHash {
		return nil, errors.New("archive SHA256 mismatch")
	}
	files, e := unpack(raw)
	if e != nil {
		return nil, e
	}
	if digest(files["install.ps1"]) != o.installerHash {
		return nil, errors.New("reviewed installer SHA256 mismatch")
	}
	if e := installerConstants(files["install.ps1"], o.tag, o.fingerprint, digest(files["t07-node-release-windows-amd64.exe"])); e != nil {
		return nil, e
	}
	// Parse keys only after every archive validation; never invoke downloaded code.
	keyBytes, e := boundedFile(o.key, 4096)
	if e != nil {
		return nil, e
	}
	defer clear(keyBytes)
	key, pub, e := signingKey(keyBytes, o.fingerprint)
	if e != nil {
		return nil, e
	}
	defer clear(key)
	m := manifest{1, "ed25519", "selfuse", o.tag, []artifact{{"windows-amd64", nodeName, int64(len(files[nodeName])), digest(files[nodeName])}}}
	mb, e := encoded(m)
	if e != nil {
		return nil, e
	}
	sig := ed25519.Sign(key, mb)
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), mb, sig) {
		return nil, errors.New("signature self-check failed")
	}
	files["deepseek-manifest-windows.json"] = mb
	files["deepseek-manifest-windows.json.sig"] = sig
	files["release.pub.pem"] = pub
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	index := releaseIndex{o.runID, 1, "GameRisker/lattice", o.source, o.tag, o.archiveHash, o.fingerprint, nil}
	for _, n := range names {
		index.Files = append(index.Files, fileRecord{n, int64(len(files[n])), digest(files[n])})
	}
	ib, e := encoded(index)
	if e != nil {
		return nil, e
	}
	files["release-index.json"] = ib
	files["release-index.json.sig"] = ed25519.Sign(key, ib)
	names = append(names, "release-index.json", "release-index.json.sig")
	sort.Strings(names)
	var sums bytes.Buffer
	for _, n := range names {
		fmt.Fprintf(&sums, "%s  %s\n", digest(files[n]), n)
	}
	files["SHA256SUMS"] = sums.Bytes()
	return files, nil
}
func packageRelease(o options) error {
	files, e := prepare(o)
	if e != nil {
		return e
	}
	// Never merge into an existing directory or follow an output symlink.
	if e = os.Mkdir(o.out, 0700); e != nil {
		return e
	}
	for n, b := range files {
		f, e := os.OpenFile(filepath.Join(o.out, n), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(b)
		ce := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
	}
	return nil
}
func main() {
	var o options
	var verifyDir string
	flag.StringVar(&verifyDir, "verify-dir", "", "verify a signed directory without private key")
	flag.StringVar(&o.archive, "archive", "", "downloaded ZIP path")
	flag.StringVar(&o.archiveHash, "archive-sha256", "", "approved archive SHA256")
	flag.StringVar(&o.installerHash, "installer-sha256", "", "reviewed installer SHA256")
	flag.StringVar(&o.key, "key", "", "dedicated PKCS8 Ed25519 private PEM path")
	flag.StringVar(&o.fingerprint, "public-key-sha256", "", "independent PKIX DER public-key SHA256")
	flag.StringVar(&o.tag, "tag", "", "new self-use release tag")
	flag.StringVar(&o.source, "source-sha", "", "reviewed source commit")
	flag.StringVar(&o.runID, "source-run-id", "", "reviewed source workflow run ID")
	flag.StringVar(&o.out, "out", "", "new output directory")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected arguments")
		os.Exit(1)
	}
	var err error
	if verifyDir != "" {
		err = verifyDirectory(verifyDir, o)
	} else {
		err = packageRelease(o)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
