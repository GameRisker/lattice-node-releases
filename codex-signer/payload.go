package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"debug/buildinfo"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

func expectedManifest(files map[string][]byte, tag string) manifest {
	m := manifest{SchemaVersion: 1, SignatureType: "ed25519", Channel: "codex-unix-root2", Version: tag}
	for _, p := range platforms {
		n := "codex-node-agent-" + p
		m.Artifacts = append(m.Artifacts, artifact{p, n, int64(len(files[n])), digest(files[n])})
	}
	return m
}

func validatePayload(files map[string][]byte, o options) error {
	if digest(files["install.sh"]) != o.installerHash {
		return errors.New("installer digest mismatch")
	}
	for _, p := range platforms {
		parts := strings.Split(p, "-")
		for _, program := range []string{"codex-node-agent", "t07-node-release"} {
			info, e := buildinfo.Read(bytes.NewReader(files[program+"-"+p]))
			if e != nil {
				return fmt.Errorf("invalid Go build metadata: %s-%s", program, p)
			}
			expected := "lattice/t07-node-release"
			if program == "codex-node-agent" {
				expected = "lattice/codex-node-agent/cmd/codex-node-agent"
			}
			if info.Path != expected {
				return errors.New("unexpected binary module")
			}
			settings := map[string]string{}
			for _, s := range info.Settings {
				settings[s.Key] = s.Value
			}
			if settings["GOOS"] != parts[0] || settings["GOARCH"] != parts[1] {
				return errors.New("binary platform mismatch")
			}
			if program == "codex-node-agent" {
				values, e := linkerValues(settings["-ldflags"])
				if e != nil {
					return e
				}
				const prefix = "lattice/codex-node-agent/internal/buildinfo."
				if values[prefix+"ReleaseNamespace"] != "codex-unix-root2" || values[prefix+"Version"] != o.tag || values[prefix+"Commit"] != o.source {
					return errors.New("binary channel/version/source mismatch")
				}
			}
		}
	}
	return installerConstants(files, o)
}

func linkerValues(raw string) (map[string]string, error) {
	values := map[string]string{}
	args := strings.Fields(raw)
	for i := 0; i < len(args); i++ {
		value := ""
		if args[i] == "-X" {
			i++
			if i >= len(args) {
				return nil, errors.New("invalid linker flags")
			}
			value = args[i]
		} else if strings.HasPrefix(args[i], "-X=") {
			value = strings.TrimPrefix(args[i], "-X=")
		}
		if value == "" {
			continue
		}
		name, val, ok := strings.Cut(value, "=")
		if !ok {
			return nil, errors.New("invalid linker assignment")
		}
		if _, exists := values[name]; exists {
			return nil, errors.New("duplicate linker assignment")
		}
		values[name] = val
	}
	return values, nil
}

// These are drift assertions, not a shell sandbox. The reviewed WHOLE-FILE
// installer hash and immutable source provenance remain required boundaries.
func installerConstants(files map[string][]byte, o options) error {
	text := string(files["install.sh"])
	if strings.Contains(text, "\r") || !strings.HasPrefix(text, "#!/usr/bin/env bash\n") {
		return errors.New("unexpected installer encoding")
	}
	for name, want := range map[string]string{
		"release_url":     "https://github.com/GameRisker/lattice-node-releases/releases/download/" + o.tag,
		"key_fingerprint": o.fingerprint, "codex_channel": "root2", "trusted_hub": "https://hub.gamerisker.com",
	} {
		assignment := regexp.MustCompile(`(?m)^[\t ]*` + name + `[\t ]*=`)
		if len(assignment.FindAllStringIndex(text, -1)) != 1 || !strings.Contains(text, "\n"+name+"='"+want+"'\n") {
			return errors.New("installer constant missing, duplicated or mismatched")
		}
	}
	for _, spec := range []struct{ platform, prefix string }{
		{"darwin-arm64", "  Darwin/arm64) platform=darwin-arm64; verifier_hash="},
		{"linux-amd64", "  Linux/x86_64|Linux/amd64) platform=linux-amd64; verifier_hash="},
		{"linux-arm64", "  Linux/aarch64|Linux/arm64) platform=linux-arm64; verifier_hash="},
	} {
		line := spec.prefix + "'" + digest(files["t07-node-release-"+spec.platform]) + "' ;;"
		if strings.Count(text, spec.prefix) != 1 || !strings.Contains(text, "\n"+line+"\n") {
			return errors.New("installer verifier binding mismatch")
		}
	}
	for _, constant := range []string{
		"codex_channel='root2'",
		"  download_program=codex-unix-root2",
		`--manifest-url "${hub%/}/downloads/${download_program}/manifest-v2.json"`,
		`[[ "$(hash_file "$work/verifier")" = "$verifier_hash" ]] || fail`,
		`  (( ! reinstall )) || fail`,
		`  [[ ! -e "$config_dir/agent.json" && ! -L "$config_dir/agent.json" ]] || fail`,
	} {
		if strings.Count(text, constant) != 1 {
			return errors.New("installer root2 safety binding missing or duplicated")
		}
	}
	startMarker := "cat > \"$work/release.pub.pem\" <<'LATTICE_PUBLIC_KEY'\n"
	if strings.Count(text, startMarker) != 1 || strings.Count(text, "\nLATTICE_PUBLIC_KEY\n") != 1 {
		return errors.New("installer embedded key boundary mismatch")
	}
	rest := strings.SplitN(text, startMarker, 2)[1]
	keyText := strings.SplitN(rest, "\nLATTICE_PUBLIC_KEY\n", 2)[0] + "\n"
	block, extra := pem.Decode([]byte(keyText))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(extra)) != 0 || digest(block.Bytes) != o.fingerprint {
		return errors.New("installer public key pin mismatch")
	}
	pub, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return errors.New("invalid installer public key")
	}
	if _, ok := pub.(ed25519.PublicKey); !ok {
		return errors.New("installer key must be Ed25519")
	}
	return nil
}
