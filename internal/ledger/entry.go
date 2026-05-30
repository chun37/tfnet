// Package ledger implements the membership ledger described in
// docs/wg-evpn-l2vpn-design.md §3.
//
// An entry is the unit of state change. Each entry advances the ledger by
// one sequence number, chains to its predecessor by hash, and is committed
// only when the N-of-N approval rule is satisfied.
package ledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
)

// Op is the operation kind of a ledger entry.
type Op string

const (
	// OpGenesis seeds the ledger with one or more initial members in a single
	// entry. Required approvers = the listed subjects. Only valid at seq=0.
	OpGenesis Op = "GENESIS"
	// OpAdd adds one new member. Required approvers = existing members ∪ {new}.
	OpAdd Op = "ADD"
	// OpRemove removes one existing member. Required approvers = members \ {target}.
	OpRemove Op = "REMOVE"
)

// Subject is the authorisation target of an entry: a node's stable identifiers.
//
// Endpoint is intentionally NOT part of the canonical hash (see §3.4): endpoint
// IP:port changes are common and signing-cost-prohibitive, so they roam via
// WireGuard's own mechanism rather than the ledger.
type Subject struct {
	NodeID         string `json:"node_id"`
	IdentityPubkey string `json:"identity_pubkey"` // base64 Ed25519 (32 bytes)
	WGPubkey       string `json:"wg_pubkey"`       // base64 Curve25519 (32 bytes)
	OverlayIP      string `json:"overlay_ip"`      // CIDR, e.g. "10.99.0.1/32"
	Endpoint       string `json:"endpoint,omitempty"`
}

// Entry is one append to the ledger.
type Entry struct {
	Seq       uint64            `json:"seq"`
	PrevHash  string            `json:"prev_hash"` // hex(SHA256), 64 chars; all-zero for seq=0
	Op        Op                `json:"op"`
	Subject   *Subject          `json:"subject,omitempty"`  // ADD / REMOVE
	Subjects  []Subject         `json:"subjects,omitempty"` // GENESIS
	Approvals map[string]string `json:"approvals"`          // node_id -> base64 Ed25519 sig
}

// ZeroHash is the prev_hash value used by the seq=0 entry.
const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Hash returns the canonical SHA256 of an entry's payload (everything except
// approvals — approvals sign over this hash).
func (e *Entry) Hash() ([32]byte, error) {
	payload, err := e.canonicalPayload()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(payload), nil
}

// HashHex is a hex-string convenience wrapper around Hash.
func (e *Entry) HashHex() (string, error) {
	h, err := e.Hash()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h[:]), nil
}

func (e *Entry) canonicalPayload() ([]byte, error) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, e.Seq)

	prev, err := hex.DecodeString(e.PrevHash)
	if err != nil {
		return nil, fmt.Errorf("prev_hash: %w", err)
	}
	if len(prev) != 32 {
		return nil, fmt.Errorf("prev_hash must be 32 bytes, got %d", len(prev))
	}
	buf.Write(prev)

	if err := writeLenStr(&buf, string(e.Op)); err != nil {
		return nil, err
	}

	switch e.Op {
	case OpGenesis:
		if e.Subject != nil {
			return nil, errors.New("GENESIS must use 'subjects' (list), not 'subject'")
		}
		if len(e.Subjects) == 0 {
			return nil, errors.New("GENESIS requires at least one subject")
		}
		subs := append([]Subject(nil), e.Subjects...)
		sort.Slice(subs, func(i, j int) bool { return subs[i].NodeID < subs[j].NodeID })
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(subs)))
		buf.Write(lb[:])
		for _, s := range subs {
			cs, err := canonicalSubject(s)
			if err != nil {
				return nil, err
			}
			buf.Write(cs)
		}
	case OpAdd, OpRemove:
		if e.Subject == nil {
			return nil, fmt.Errorf("%s requires 'subject'", e.Op)
		}
		if len(e.Subjects) != 0 {
			return nil, fmt.Errorf("%s must not set 'subjects'", e.Op)
		}
		cs, err := canonicalSubject(*e.Subject)
		if err != nil {
			return nil, err
		}
		buf.Write(cs)
	default:
		return nil, fmt.Errorf("unknown op: %q", e.Op)
	}
	return buf.Bytes(), nil
}

// canonicalSubject is the deterministic byte form of a Subject for hashing.
// Endpoint is excluded (§3.4).
func canonicalSubject(s Subject) ([]byte, error) {
	if s.NodeID == "" {
		return nil, errors.New("subject.node_id is empty")
	}
	idPub, err := base64.StdEncoding.DecodeString(s.IdentityPubkey)
	if err != nil {
		return nil, fmt.Errorf("identity_pubkey: %w", err)
	}
	if len(idPub) != 32 {
		return nil, fmt.Errorf("identity_pubkey must be 32 bytes, got %d", len(idPub))
	}
	wgPub, err := base64.StdEncoding.DecodeString(s.WGPubkey)
	if err != nil {
		return nil, fmt.Errorf("wg_pubkey: %w", err)
	}
	if len(wgPub) != 32 {
		return nil, fmt.Errorf("wg_pubkey must be 32 bytes, got %d", len(wgPub))
	}
	if _, err := netip.ParsePrefix(s.OverlayIP); err != nil {
		return nil, fmt.Errorf("overlay_ip: %w", err)
	}

	var buf bytes.Buffer
	if err := writeLenStr(&buf, s.NodeID); err != nil {
		return nil, err
	}
	buf.Write(idPub)
	buf.Write(wgPub)
	if err := writeLenStr(&buf, s.OverlayIP); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeLenStr(w io.Writer, s string) error {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	if _, err := w.Write(l[:]); err != nil {
		return err
	}
	_, err := io.WriteString(w, s)
	return err
}
