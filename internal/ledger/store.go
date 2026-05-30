package ledger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Store is the on-disk home of a ledger. Layout:
//
//	<dir>/log.jsonl      append-only confirmed entries, one JSON per line
//	<dir>/pending/       proposed entries collecting signatures
type Store struct {
	Dir string
}

func (s *Store) LogPath() string     { return filepath.Join(s.Dir, "log.jsonl") }
func (s *Store) PendingDir() string  { return filepath.Join(s.Dir, "pending") }
func (s *Store) PendingPath(name string) string {
	return filepath.Join(s.PendingDir(), name)
}

// Init creates the directory structure if it does not already exist.
func (s *Store) Init() error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(s.PendingDir(), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(s.LogPath()); os.IsNotExist(err) {
		f, err := os.OpenFile(s.LogPath(), os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_ = f.Close()
	}
	return nil
}

// LoadEntries returns all confirmed entries in order.
func (s *Store) LoadEntries() ([]Entry, error) {
	f, err := os.Open(s.LogPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var entries []Entry
	dec := json.NewDecoder(f)
	for {
		var e Entry
		if err := dec.Decode(&e); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode entry %d: %w", len(entries), err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// Replay loads entries from disk and applies them to a fresh State, returning
// both. On any failure the State is the partial one up to the failing entry.
func (s *Store) Replay() (*State, []Entry, error) {
	entries, err := s.LoadEntries()
	if err != nil {
		return nil, nil, err
	}
	st := NewState()
	for i := range entries {
		if err := st.Apply(&entries[i]); err != nil {
			return st, entries, fmt.Errorf("entry %d (seq=%d, op=%s): %w",
				i, entries[i].Seq, entries[i].Op, err)
		}
	}
	return st, entries, nil
}

// Append writes a single confirmed entry to the log. It does NOT validate.
// Validate via State.Apply before calling.
func (s *Store) Append(e *Entry) error {
	f, err := os.OpenFile(s.LogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// SavePending stores a proposed entry as a directory:
//
//	<pending>/<seq>-<hash12>/
//	    entry.json     The entry (with empty approvals).
//	    sigs/          Empty; signers populate this dir.
//
// Returns the absolute path of the directory.
func (s *Store) SavePending(e *Entry) (string, error) {
	name, err := PendingName(e)
	if err != nil {
		return "", err
	}
	dir := s.PendingPath(name)
	if err := os.MkdirAll(filepath.Join(dir, "sigs"), 0o700); err != nil {
		return "", err
	}
	// entry.json must never carry approvals -- those live in sigs/.
	bare := *e
	bare.Approvals = nil
	if err := SaveEntryFile(filepath.Join(dir, "entry.json"), &bare); err != nil {
		return "", err
	}
	return dir, nil
}

// LoadEntryFile reads a single entry from a JSON file (used for pending entries).
func LoadEntryFile(path string) (*Entry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var e Entry
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return &e, nil
}

// SaveEntryFile writes a single entry to a pretty-printed JSON file.
func SaveEntryFile(path string, e *Entry) error {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
