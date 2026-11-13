package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"regexp"
	"strings"
)

// Validate public constants as data, not PowerShell. This is a drift guard, not
// a sandbox or proof that arbitrary PowerShell is safe: the reviewed whole-file
// digest and reviewed source commit remain mandatory security boundaries.
func installerConstants(script []byte, tag, pin, verifierHash string) error {
	text := strings.ReplaceAll(string(script), "\r\n", "\n")
	verifierMarker := "if ((Get-FileHash -Algorithm SHA256 -LiteralPath $verify).Hash.ToLowerInvariant() -cne '"
	if !hashRE.MatchString(verifierHash) || strings.Count(text, verifierMarker) != 1 {
		return errors.New("installer verifier check missing or duplicated")
	}
	verifierLine := regexp.MustCompile(`(?m)^  if \(\(Get-FileHash -Algorithm SHA256 -LiteralPath \$verify\).Hash.ToLowerInvariant\(\) -cne '([a-f0-9]{64})'\) \{ throw '安装校验工具指纹不符，未执行。' \}$`)
	verifierMatches := verifierLine.FindAllStringSubmatch(text, -1)
	if len(verifierMatches) != 1 || verifierMatches[0][1] != verifierHash {
		return errors.New("installer verifier digest mismatch or changed check")
	}

	for _, item := range []struct{ name, expected string }{
		{"release", "https://github.com/GameRisker/lattice-node-releases/releases/download/" + tag},
		{"keyFingerprint", pin},
	} {
		assign := regexp.MustCompile(`(?im)^[\t ]*\$` + item.name + `[\t ]*=`)
		if len(assign.FindAllStringIndex(text, -1)) != 1 {
			return errors.New("installer constant assignment missing or duplicated")
		}
		line := regexp.MustCompile(`(?m)^\$` + item.name + ` = Decode '([A-Za-z0-9+/]+={0,2})'$`)
		matches := line.FindAllStringSubmatch(text, -1)
		if len(matches) != 1 {
			return errors.New("installer constant syntax differs from reviewed template")
		}
		decoded, e := base64.StdEncoding.Strict().DecodeString(matches[0][1])
		if e != nil || string(decoded) != item.expected {
			return errors.New("installer constant does not match release inputs")
		}
	}
	keyUse := regexp.MustCompile(`(?i)\[IO\.File\]::WriteAllBytes\([\t ]*\$key[\t ]*,`)
	if len(keyUse.FindAllStringIndex(text, -1)) != 1 {
		return errors.New("installer embedded key write missing or duplicated")
	}
	keyLine := regexp.MustCompile(`(?m)^  \[IO\.File\]::WriteAllBytes\(\$key,\[Convert\]::FromBase64String\('([A-Za-z0-9+/]+={0,2})'\)\)$`)
	matches := keyLine.FindAllStringSubmatch(text, -1)
	if len(matches) != 1 {
		return errors.New("installer embedded key syntax changed")
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(matches[0][1])
	if e != nil {
		return errors.New("invalid embedded key encoding")
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 || digest(block.Bytes) != pin {
		return errors.New("installer embedded key pin mismatch")
	}
	parsed, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return errors.New("invalid embedded public key")
	}
	if _, ok := parsed.(ed25519.PublicKey); !ok {
		return errors.New("embedded public key is not Ed25519")
	}
	return nil
}
