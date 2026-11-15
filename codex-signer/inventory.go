package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type verifiedRecord struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Hash only the exact in-memory snapshot that just passed verification. Never
// re-open mutable payload paths to establish the publisher's expected digests.
func writeVerifiedInventory(signedDir, out string, files map[string][]byte) error {
	dir, err := filepath.Abs(signedDir)
	if err != nil {
		return err
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	path, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return err
	}
	path = filepath.Join(parent, filepath.Base(path))
	relative, err := filepath.Rel(dir, path)
	if err != nil {
		return err
	}
	if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))) {
		return errors.New("inventory output must be outside signed directory")
	}
	inventory := map[string]verifiedRecord{}
	for name, body := range files {
		inventory[name] = verifiedRecord{int64(len(body)), digest(body)}
	}
	body, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
