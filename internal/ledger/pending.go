package ledger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Pending is a proposed entry being collected for signatures.
//
// On disk it is a directory under <ledger>/pending/, laid out so that every
// signer adds a separate file -- never modifying a shared one. This makes the
// pending state safe to distribute via a shared git repo, where concurrent
// signing would otherwise create merge conflicts.
//
//	<ledger>/pending/000003-1e16464abc/
//	    entry.json              The proposal (Entry with empty approvals).
//	                            Written once by the proposer; never modified.
//	    sigs/
//	        alice.json          One detached SigFile per signer.
//	        bob.json
type Pending struct {
	Dir   string
	Entry *Entry // entry.json with approvals populated from sigs/
}

// SigFile is the on-disk form of a single detached signature, as produced by
// `tfnet ledger sign -out` and consumed by `tfnet ledger merge`.
type SigFile struct {
	NodeID    string `json:"node_id"`
	EntryHash string `json:"entry_hash"`
	Signature string `json:"signature"` // base64 Ed25519 signature
}

// EntryFile returns the path to entry.json inside the pending dir.
func (p *Pending) EntryFile() string { return filepath.Join(p.Dir, "entry.json") }

// SigsDir returns the path to the sigs/ subdirectory.
func (p *Pending) SigsDir() string { return filepath.Join(p.Dir, "sigs") }

// SigFilePath returns where a signature from nodeID would live.
func (p *Pending) SigFilePath(nodeID string) string {
	return filepath.Join(p.SigsDir(), nodeID+".json")
}

// PendingName returns the conventional directory name for a proposed entry:
// "<seq:06d>-<hash:12hex>". Two different proposals at the same seq still
// receive different names because the hash differs.
func PendingName(e *Entry) (string, error) {
	h, err := e.Hash()
	if err != nil {
		return "", err
	}
	const hexdigits = "0123456789abcdef"
	hb := h[:6]
	out := make([]byte, 12)
	for i, b := range hb {
		out[i*2] = hexdigits[b>>4]
		out[i*2+1] = hexdigits[b&0xf]
	}
	return fmt.Sprintf("%06d-%s", e.Seq, string(out)), nil
}

// LoadPending opens dir, parses entry.json, and merges every sigs/*.json
// into entry.Approvals (in memory only — the files on disk stay separate).
//
// Each signature whose entry_hash field is set must match the computed hash
// of entry.json; mismatches reject the load.
func LoadPending(dir string) (*Pending, error) {
	p := &Pending{Dir: dir}
	e, err := LoadEntryFile(p.EntryFile())
	if err != nil {
		return nil, err
	}
	if e.Approvals == nil {
		e.Approvals = map[string]string{}
	}
	sigs, err := ReadSigsDir(p.SigsDir())
	if err != nil {
		return nil, err
	}
	h, err := e.HashHex()
	if err != nil {
		return nil, err
	}
	for _, s := range sigs {
		if s.EntryHash != "" && s.EntryHash != h {
			return nil, fmt.Errorf("%s/sigs/%s.json: entry_hash mismatch (sig is for a different entry)",
				dir, s.NodeID)
		}
		e.Approvals[s.NodeID] = s.Signature
	}
	p.Entry = e
	return p, nil
}

// ReadSigsDir parses every *.json in dir as a SigFile. Missing dir returns nil.
func ReadSigsDir(dir string) ([]SigFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []SigFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var s SigFile
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if s.NodeID == "" || s.Signature == "" {
			return nil, fmt.Errorf("%s: missing node_id or signature", e.Name())
		}
		out = append(out, s)
	}
	return out, nil
}

// SaveSig writes a SigFile into the pending dir's sigs/ subdirectory.
// Idempotent: writing the same signature twice is a no-op write.
func (p *Pending) SaveSig(s SigFile) error {
	if s.NodeID == "" || s.Signature == "" {
		return fmt.Errorf("SaveSig: empty node_id or signature")
	}
	if err := os.MkdirAll(p.SigsDir(), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p.SigFilePath(s.NodeID), append(b, '\n'), 0o600)
}

// Remove deletes the entire pending directory. Called after a successful commit.
func (p *Pending) Remove() error {
	return os.RemoveAll(p.Dir)
}
